// Copyright (c) 2016-2019 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
// Copyright (c) 2020-2021 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package scalar implements arithmetic on scalars (integers mod the group
// order).
package scalar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/oasisprotocol/curve25519-voi/internal/disalloweq"
	"github.com/oasisprotocol/curve25519-voi/internal/subtle"
)

const (
	// ScalarSize is the size of a scalar in bytes.
	ScalarSize = 32

	// ScalarWideSize is the size of a wide scalar in bytes.
	ScalarWideSize = 64
)

var errScalarNotCanonical = fmt.Errorf("curve/scalar: representative not canonical")

// Scalar holds an integer s < 2^255 which represents an element of
// Z/L.
type Scalar struct {
	disalloweq.DisallowEqual //nolint:unused
	inner                    [ScalarSize]byte
}

// FromBytesModOrder constructs a scalar by reducing a 256-bit
// little-endian integer modulo the group order L.
func (s *Scalar) FromBytesModOrder(in []byte) error {
	if len(in) != ScalarSize {
		return fmt.Errorf("curve/scalar: unexpected input size")
	}

	// Temporarily allow s_unreduced.bytes > 2^255 ...
	copy(s.inner[:], in)

	// Then reduce mod the group order.
	s.Reduce()

	return nil
}

// FromBytesModOrderWide constructs a scalar by reducing a 512-bit
// little-endian integer modulo the group order L.
func (s *Scalar) FromBytesModOrderWide(in []byte) error {
	var us unpackedScalar
	if err := us.fromBytesWide(in); err != nil {
		return err
	}

	s.pack(&us)

	return nil
}

// FromCanonicalBytes attempts to construct a scalar from a canoical byte
// representation.
func (s *Scalar) FromCanonicalBytes(in []byte) error {
	var candidate Scalar
	if err := candidate.FromBits(in); err != nil {
		return err
	}

	// Check that the high bit is not set, and that the candidate is
	// canonical.
	if in[31]>>7 != 0 || !candidate.IsCanonical() {
		return errScalarNotCanonical
	}

	*s = candidate

	return nil
}

// FromBits constructs a scalar from the low 255 bits of a 256-bit integer.
//
// This function is intended for applications like X25519 which
// require specific bit-patterns when performing scalar
// multiplication.
func (s *Scalar) FromBits(in []byte) error {
	if len(in) != ScalarSize {
		return fmt.Errorf("curve/scalar: unexpected input size")
	}

	copy(s.inner[:], in)
	// Ensure that s < 2^255 by masking the high bit
	s.inner[31] &= 0b0111_1111

	return nil
}

// Equal returns 1 iff the scalars are equal, 0 otherwise.
// This function will execute in constant-time.
func (s *Scalar) Equal(other *Scalar) int {
	return subtle.ConstantTimeCompareBytes(s.inner[:], other.inner[:])
}

// Mul computes `a * b` (mod l).
func (s *Scalar) Mul(a, b *Scalar) {
	var unpackedS unpackedScalar

	unpackedA, unpackedB := a.unpack(), b.unpack()
	unpackedS.mul(&unpackedA, &unpackedB)
	s.pack(&unpackedS)
}

// Add computes `a + b` (mod l).
func (s *Scalar) Add(a, b *Scalar) {
	var unpackedS unpackedScalar
	unpackedA, unpackedB := a.unpack(), b.unpack()

	// The unpackedScalar.Add function produces reduced outputs
	// if the inputs are reduced.  However, these inputs may not
	// be reduced -- they might come from Scalar.FromBits.  So
	// after computing the sum, we explicitly reduce it mod l
	// before repacking.
	unpackedS.add(&unpackedA, &unpackedB)
	z := scalarMulInternal(&unpackedS, &constR)
	unpackedS.montgomeryReduce(&z)
	s.pack(&unpackedS)
}

// Sub computes `a - b` (mod l).
func (s *Scalar) Sub(a, b *Scalar) {
	var unpackedS unpackedScalar
	unpackedA, unpackedB := a.unpack(), b.unpack()

	// The unpackedScalar.Sub function requires reduced inputs
	// and produces reduced output. However, these inputs may not
	// be reduced -- they might come from Scalar.FromBits.  So
	// we explicitly reduce the inputs.
	z := scalarMulInternal(&unpackedA, &constR)
	unpackedA.montgomeryReduce(&z)
	z = scalarMulInternal(&unpackedB, &constR)
	unpackedB.montgomeryReduce(&z)
	unpackedS.sub(&unpackedA, &unpackedB)
	s.pack(&unpackedS)
}

// Neg computes `-s`.
func (s *Scalar) Neg() {
	var zero unpackedScalar
	unpackedS := s.unpack()

	z := scalarMulInternal(&unpackedS, &constR)
	unpackedS.montgomeryReduce(&z)
	unpackedS.sub(&zero, &unpackedS)
	s.pack(&unpackedS)
}

// ConditionalSelect sets the scalar to a iff choice == 0 and
// b iff choice == 1.
func (s *Scalar) ConditionalSelect(a, b *Scalar, choice int) {
	// TODO/perf: This will be kind of slow, consider optimizing it
	// if the call is used frequently enough to matter.

	// Note: The rust subtle crate has inverted choice behavior for
	// select vs the go runtime library package.
	for i := range s.inner {
		s.inner[i] = subtle.ConstantTimeSelectByte(choice, b.inner[i], a.inner[i])
	}
}

// Product sets the scalar to the product of a slice of scalars.
func (s *Scalar) Product(values []*Scalar) {
	s.FromUint64(1)

	for _, v := range values {
		s.Mul(s, v)
	}
}

// Sum sets the scalar to the sum of a slice of scalars.
func (s *Scalar) Sum(values []*Scalar) {
	s.Zero()

	for _, v := range values {
		s.Add(s, v)
	}
}

// FromUint64 sets the scalar to the given uint64.
func (s *Scalar) FromUint64(x uint64) {
	var sBytes [ScalarSize]byte
	binary.LittleEndian.PutUint64(sBytes[0:8], x)
	s.inner = sBytes
}

// Random sets the scalar to one chosen uniformly at random using entropy
// from the user-provided io.Reader.  If rng is nil, the runtime library's
// entropy source will be used.
func (s *Scalar) Random(rng io.Reader) error {
	var scalarBytes [ScalarWideSize]byte

	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, scalarBytes[:]); err != nil {
		return fmt.Errorf("curve/scalar: failed to read entropy: %w", err)
	}

	return s.FromBytesModOrderWide(scalarBytes[:])
}

// ToBytes packs the scalar into 32 bytes.
func (s *Scalar) ToBytes(out []byte) error {
	if len(out) != ScalarSize {
		return fmt.Errorf("curve/scalar: unexpected output size")
	}

	copy(out, s.inner[:])

	return nil
}

// Zero sets the scalar to zero.
func (s *Scalar) Zero() {
	for i := range s.inner {
		s.inner[i] = 0
	}
}

// One sets the scalar to one.
func (s *Scalar) One() {
	s.inner = [ScalarSize]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
}

// Invert sets the nonzero scalar to its multiplicative inverse.
//
// WARNING: The scalar MUST be nonzero.  If you cannot prove that this is
// the case you MUST not use this function.
func (s *Scalar) Invert() {
	x := s.unpack()
	x.Invert()
	s.pack(&x)
}

// BatchInvert computes the inverses of slice of `Scalar`s in a batch,
// and sets the scalar to the product of all inverses.  Each element
// of the input slice is replaced by its inverse.
//
// WARNING: The input scalars MUST be nonzero.  If you cannot prove
// that this is the case you MUST not use this function.
func (s *Scalar) BatchInvert(inputs []*Scalar) {
	n := len(inputs)
	one := func() unpackedScalar {
		tmp := One()
		r := tmp.unpack()
		r.toMontgomery()
		return r
	}()

	// TODO: In theory this should be sanitized.
	scratch := make([]unpackedScalar, 0, n)

	// Keep an accumulator of all of the previous products.
	acc := one
	for i, input := range inputs {
		scratch = append(scratch, acc)

		// Avoid unnecessary Montgomery multiplication in second pass by
		// keeping inputs in Montgomery form.
		tmp := input.unpack()
		tmp.toMontgomery()
		inputs[i].pack(&tmp)
		acc.montgomeryMul(&acc, &tmp)
	}

	// Compute the inverse of all products.
	acc.montgomeryInvert()
	acc.fromMontgomery()

	// We need to return the product of all inverses later.
	var ret Scalar
	ret.pack(&acc)

	// Pass through the vector backwards to compute the inverses
	// in place.
	for i := n - 1; i >= 0; i-- {
		input, scratch := inputs[i], scratch[i]
		unpackedInput := input.unpack()
		var tmp, tmp2 unpackedScalar
		tmp.montgomeryMul(&acc, &unpackedInput)
		tmp2.montgomeryMul(&acc, &scratch)
		inputs[i].pack(&tmp2)
		acc = tmp
	}

	*s = ret
}

// Bits gets the bits of the scalar.
func (s *Scalar) Bits() [8 * ScalarSize]byte {
	var out [8 * ScalarSize]byte

	for i := range out {
		out[i] = (s.inner[i>>3] >> (i & 7)) & 1
	}

	return out
}

// NonAdjacentForm returns a width-w "Non-Adjacent Form" of this scalar.
func (s *Scalar) NonAdjacentForm(w uint) [256]int8 {
	if w < 2 || w > 8 {
		panic("curve/scalar: invalid width parameter")
	}

	var (
		naf [256]int8
		x   [5]uint64
	)
	for i := 0; i < 4; i++ {
		x[i] = binary.LittleEndian.Uint64(s.inner[i*8:])
	}

	width := uint64(1 << w)
	windowMask := uint64(width - 1)

	var (
		pos   uint
		carry uint64
	)
	for pos < 256 {
		// Construct a buffer of bits of the scalar, starting at bit `pos`
		idx := pos / 64
		bitIdx := pos % 64
		var bitBuf uint64
		if bitIdx < 64-w {
			// This window's bits are contained in a single u64
			bitBuf = x[idx] >> bitIdx
		} else {
			// Combine the current u64's bits with the bits from the next u64
			bitBuf = (x[idx] >> bitIdx) | (x[1+idx] << (64 - bitIdx))
		}

		// Add the carry into the current window
		window := carry + (bitBuf & windowMask)

		if window&1 == 0 {
			// If the window value is even, preserve the carry and continue.
			// Why is the carry preserved?
			// If carry == 0 and window & 1 == 0, then the next carry should be 0
			// If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
			pos += 1
			continue
		}

		if window < width/2 {
			carry = 0
			naf[pos] = int8(window)
		} else {
			carry = 1
			naf[pos] = int8(window) - int8(width)
		}

		pos += w
	}

	return naf
}

// ToRadix16 returns the scalar in radix 16, with coefficients in [-8,8).
func (s *Scalar) ToRadix16() [64]int8 {
	var output [64]int8

	// Step 1: change radix.
	// Convert from radix 256 (bytes) to radix 16 (nibbles)
	botHalf := func(x uint8) uint8 {
		return (x >> 0) & 15
	}
	topHalf := func(x uint8) uint8 {
		return (x >> 4) & 15
	}

	for i := 0; i < 32; i++ {
		output[2*i] = int8(botHalf(s.inner[i]))
		output[2*i+1] = int8(topHalf(s.inner[i]))
	}
	// Precondition note: since self[31] <= 127, output[63] <= 7

	// Step 2: recenter coefficients from [0,16) to [-8,8)
	for i := 0; i < 63; i++ {
		carry := (output[i] + 8) >> 4
		output[i] -= carry << 4
		output[i+1] += carry
	}
	// Precondition note: output[63] is not recentered.  It
	// increases by carry <= 1.  Thus output[63] <= 8.

	return output
}

// ToRadix2wSizeHint returns a size hint indicating how many entries of
// the return value of ToRadix2w are nonzero.
func ToRadix2wSizeHint(w uint) uint {
	switch w {
	case 6, 7:
		return (256 + w - 1) / w
	case 8:
		// See comment in toRadix2w on handling the terminal carry.
		return (256+w-1)/w + 1
	default:
		panic("curve/scalar: invalid radix parameter")
	}
}

// ToRadix2w returns a representation of a scalar in radix 64, 128, or 256.
func (s *Scalar) ToRadix2w(w uint) [43]int8 {
	_ = ToRadix2wSizeHint(w)

	// Scalar formatted as four `uint64`s with the carry bit packed
	// into the highest bit.
	var scalar64x4 [4]uint64
	for i := 0; i < 4; i++ {
		scalar64x4[i] = binary.LittleEndian.Uint64(s.inner[i*8:])
	}

	radix := uint64(1 << w)
	windowMask := radix - 1
	digitsCount := (254 + w - 1) / w

	var (
		carry  uint64
		digits [43]int8
	)
	for i := uint(0); i < digitsCount; i++ {
		// Construct a buffer of bits of the scalar, starting at `bitOffset`.
		bitOffset := i * w
		u64Idx := bitOffset / 64
		bitIdx := bitOffset % 64

		// Read the bits from the scalar.
		var bitBuf uint64
		if bitIdx < 64-w || u64Idx == 3 {
			// This window's bits are contained in a single uint64,
			// or it's the last uint64 anyway.
			bitBuf = scalar64x4[u64Idx] >> bitIdx
		} else {
			// Combine the current u64's bits with the bits from the next u64
			bitBuf = (scalar64x4[u64Idx] >> bitIdx) | (scalar64x4[1+u64Idx] << (64 - bitIdx))
		}

		// Read the actual coefficient value from the window
		coef := carry + (bitBuf & windowMask) // coef = [0, 2^r)

		// Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
		carry = (coef + (radix / 2)) >> w
		digits[i] = int8(int64(coef) - int64(carry<<w))
	}

	// When w < 8, we can fold the final carry onto the last digit d,
	// because d < 2^w/2 so d + carry*2^w = d + 1*2^w < 2^(w+1) < 2^8.
	//
	// When w = 8, we can't fit carry*2^w into an i8.  This should
	// not happen anyways, because the final carry will be 0 for
	// reduced scalars, but the Scalar invariant allows 255-bit scalars.
	// To handle this, we expand the size_hint by 1 when w=8,
	// and accumulate the final carry onto another digit.
	switch w {
	case 8:
		digits[digitsCount] += int8(carry)
	default:
		digits[digitsCount-1] += int8(carry << w)
	}

	return digits
}

// Reduce reduces the scalar modulo L.
func (s *Scalar) Reduce() {
	var xModL unpackedScalar
	x := s.unpack()
	xR := scalarMulInternal(&x, &constR)
	xModL.montgomeryReduce(&xR)
	s.pack(&xModL)
}

// IsCanonical checks if this scalar is the canonical representative mod L.
//
// This is intended for uses like input validation, where variable-time code
// is acceptable.
func (s *Scalar) IsCanonical() bool {
	sReduced := *s
	sReduced.Reduce()
	return bytes.Equal(s.inner[:], sReduced.inner[:])
}

func (s *Scalar) unpack() unpackedScalar {
	var us unpackedScalar
	us.fromBytes(s.inner[:])
	return us
}

func (s *Scalar) pack(us *unpackedScalar) {
	us.toBytes(s.inner[:])
}

// NewFromUint64 returns a scalar set to the given uint64.
func NewFromUint64(x uint64) Scalar {
	var s Scalar
	s.FromUint64(x)
	return s
}

// One returns a scalar set to 1.
func One() Scalar {
	var s Scalar
	s.One()
	return s
}

func newScalar(vec []byte) Scalar {
	if len(vec) != ScalarSize {
		panic("curve/scalar: invalid constant vector")
	}

	// Note: This will happily create non-canonical scalars, which is fine
	// because this is only used to define constants (e.g. L), and for
	// testing.
	var s Scalar
	copy(s.inner[:], vec)
	return s
}

// Omitted:
//  * HashFromBytes
//  * FromHash
