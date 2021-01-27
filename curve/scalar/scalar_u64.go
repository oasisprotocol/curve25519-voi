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

// +build amd64 go1.13,arm64 go1.13,ppc64le go1.13,ppc64 go1.14,s390x force64bit
// +build !force32bit

package scalar

import (
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/internal/uint128"
)

const low_52_bit_mask uint64 = (1 << 52) - 1

// unpackedScalar represents a scalar in Z/lZ as 5 52-bit limbs.
type unpackedScalar [5]uint64

// fromBytes unpacks a 32 byte / 256 bit scalar into 5 52-bit limbs.
func (s *unpackedScalar) fromBytes(in []byte) {
	if len(in) != ScalarSize {
		panic("curve/scalar/u64: unexpected input size")
	}

	var words [4]uint64
	for i := 0; i < 4; i++ {
		words[i] = binary.LittleEndian.Uint64(in[i*8:])
	}

	const top_mask uint64 = (1 << 48) - 1

	s[0] = words[0] & low_52_bit_mask
	s[1] = ((words[0] >> 52) | (words[1] << 12)) & low_52_bit_mask
	s[2] = ((words[1] >> 40) | (words[2] << 24)) & low_52_bit_mask
	s[3] = ((words[2] >> 28) | (words[3] << 36)) & low_52_bit_mask
	s[4] = (words[3] >> 16) & top_mask
}

// fromBytesWide reduces a 64 byte / 512 bit scalar mod l.
func (s *unpackedScalar) fromBytesWide(in []byte) error {
	if len(in) != ScalarWideSize {
		return fmt.Errorf("curve/scalar/u64: unexpected wide input size")
	}

	var words [8]uint64
	for i := 0; i < 8; i++ {
		words[i] = binary.LittleEndian.Uint64(in[i*8:])
	}

	var lo, hi unpackedScalar
	lo[0] = words[0] & low_52_bit_mask
	lo[1] = ((words[0] >> 52) | (words[1] << 12)) & low_52_bit_mask
	lo[2] = ((words[1] >> 40) | (words[2] << 24)) & low_52_bit_mask
	lo[3] = ((words[2] >> 28) | (words[3] << 36)) & low_52_bit_mask
	lo[4] = ((words[3] >> 16) | (words[4] << 48)) & low_52_bit_mask
	hi[0] = (words[4] >> 4) & low_52_bit_mask
	hi[1] = ((words[4] >> 56) | (words[5] << 8)) & low_52_bit_mask
	hi[2] = ((words[5] >> 44) | (words[6] << 20)) & low_52_bit_mask
	hi[3] = ((words[6] >> 32) | (words[7] << 32)) & low_52_bit_mask
	hi[4] = words[7] >> 20

	lo.montgomeryMul(&lo, &constR)  // (lo * R) / R = lo
	hi.montgomeryMul(&hi, &constRR) // (hi * R^2) / R = hi * R

	s.add(&hi, &lo) // (hi * R) + lo

	return nil
}

// toBytes packs the limbs of the scalar into 32 bytes.
func (s *unpackedScalar) toBytes(out []byte) {
	if len(out) != ScalarSize {
		panic("curve/scalar/u64: unexpected output size")
	}

	out[0] = byte(s[0] >> 0)
	out[1] = byte(s[0] >> 8)
	out[2] = byte(s[0] >> 16)
	out[3] = byte(s[0] >> 24)
	out[4] = byte(s[0] >> 32)
	out[5] = byte(s[0] >> 40)
	out[6] = byte((s[0] >> 48) | (s[1] << 4))
	out[7] = byte(s[1] >> 4)
	out[8] = byte(s[1] >> 12)
	out[9] = byte(s[1] >> 20)
	out[10] = byte(s[1] >> 28)
	out[11] = byte(s[1] >> 36)
	out[12] = byte(s[1] >> 44)
	out[13] = byte(s[2] >> 0)
	out[14] = byte(s[2] >> 8)
	out[15] = byte(s[2] >> 16)
	out[16] = byte(s[2] >> 24)
	out[17] = byte(s[2] >> 32)
	out[18] = byte(s[2] >> 40)
	out[19] = byte((s[2] >> 48) | (s[3] << 4))
	out[20] = byte(s[3] >> 4)
	out[21] = byte(s[3] >> 12)
	out[22] = byte(s[3] >> 20)
	out[23] = byte(s[3] >> 28)
	out[24] = byte(s[3] >> 36)
	out[25] = byte(s[3] >> 44)
	out[26] = byte(s[4] >> 0)
	out[27] = byte(s[4] >> 8)
	out[28] = byte(s[4] >> 16)
	out[29] = byte(s[4] >> 24)
	out[30] = byte(s[4] >> 32)
	out[31] = byte(s[4] >> 40)
}

// add computes `a + b` (mod l).
func (s *unpackedScalar) add(a, b *unpackedScalar) {
	// a + b
	var carry uint64
	for i := 0; i < 5; i++ {
		carry = a[i] + b[i] + (carry >> 52)
		s[i] = carry & low_52_bit_mask
	}

	// subtract l if the sum is >= l
	s.sub(s, &constL)
}

// sub computes `a - b` (mod l).
func (s *unpackedScalar) sub(a, b *unpackedScalar) {
	// a - b
	var borrow uint64
	for i := 0; i < 5; i++ {
		borrow = a[i] - (b[i] + (borrow >> 63))
		s[i] = borrow & low_52_bit_mask
	}

	// conditionally add l if the difference is negative
	underflow_mask := ((borrow >> 63) ^ 1) - 1
	var carry uint64
	for i := 0; i < 5; i++ {
		carry = s[i] + (constL[i] & underflow_mask) + (carry >> 52)
		s[i] = carry & low_52_bit_mask
	}
}

// fromMontgomery takes a scalar out of Montgomery form, i.e. computes `a/R (mod l)`.
func (s *unpackedScalar) fromMontgomery() {
	var limbs [9]uint128.Uint128
	for i := 0; i < 5; i++ {
		uint128.SetUint64(&limbs[i], s[i])
	}
	s.montgomeryReduce(&limbs)
}

// montgomeryReduce computes `limbs/R` (mod l), where R is the Montgomery
// modulus 2^260.
func (s *unpackedScalar) montgomeryReduce(limbs *[9]uint128.Uint128) {
	part1 := func(sum uint128.Uint128) (uint128.Uint128, uint64) {
		p := uint128.Lo(&sum) * constLFACTOR & ((1 << 52) - 1)
		carry := sum
		uint128.Mul64x64Add(&carry, p, constL[0])
		uint128.Shr(&carry, 52)
		return carry, p
	}

	part2 := func(sum uint128.Uint128) (uint128.Uint128, uint64) {
		w := uint128.Lo(&sum) & ((1 << 52) - 1)
		carry := sum
		uint128.Shr(&carry, 52)
		return carry, w
	}

	// note: l[3] is zero, so its multiples can be skipped
	l := &constL

	// the first half computes the Montgomery adjustment factor n, and begins adding n*l to make limbs divisible by R
	var (
		carry              uint128.Uint128
		n0, n1, n2, n3, n4 uint64
	)

	carry, n0 = part1(limbs[0])

	uint128.Add(&carry, &limbs[1])
	uint128.Mul64x64Add(&carry, n0, l[1])
	carry, n1 = part1(carry)

	uint128.Add(&carry, &limbs[2])
	uint128.Mul64x64Add(&carry, n0, l[2])
	uint128.Mul64x64Add(&carry, n1, l[1])
	carry, n2 = part1(carry)

	uint128.Add(&carry, &limbs[3])
	uint128.Mul64x64Add(&carry, n1, l[2])
	uint128.Mul64x64Add(&carry, n2, l[1])
	carry, n3 = part1(carry)

	uint128.Add(&carry, &limbs[4])
	uint128.Mul64x64Add(&carry, n0, l[4])
	uint128.Mul64x64Add(&carry, n2, l[2])
	uint128.Mul64x64Add(&carry, n3, l[1])
	carry, n4 = part1(carry)

	// limbs is divisible by R now, so we can divide by R by simply storing the upper half as the result
	var r0, r1, r2, r3, r4 uint64

	uint128.Add(&carry, &limbs[5])
	uint128.Mul64x64Add(&carry, n1, l[4])
	uint128.Mul64x64Add(&carry, n3, l[2])
	uint128.Mul64x64Add(&carry, n4, l[1])
	carry, r0 = part2(carry)

	uint128.Add(&carry, &limbs[6])
	uint128.Mul64x64Add(&carry, n2, l[4])
	uint128.Mul64x64Add(&carry, n4, l[2])
	carry, r1 = part2(carry)

	uint128.Add(&carry, &limbs[7])
	uint128.Mul64x64Add(&carry, n3, l[4])
	carry, r2 = part2(carry)

	uint128.Add(&carry, &limbs[8])
	uint128.Mul64x64Add(&carry, n4, l[4])
	carry, r3 = part2(carry)

	r4 = uint128.Lo(&carry)

	// result may be >= l, so attempt to subtract l
	s.sub(&unpackedScalar{r0, r1, r2, r3, r4}, l)
}

func (s *unpackedScalar) squareInternal() [9]uint128.Uint128 {
	var z [9]uint128.Uint128

	s0, s1, s2, s3, s4 := s[0], s[1], s[2], s[3], s[4]
	aa0, aa1, aa2, aa3 := s0*2, s1*2, s2*2, s3*2

	uint128.Mul64x64(&z[0], s0, s0)

	uint128.Mul64x64(&z[1], aa0, s1)

	uint128.Mul64x64(&z[2], aa0, s2)
	uint128.Mul64x64Add(&z[2], s1, s1)

	uint128.Mul64x64(&z[3], aa0, s3)
	uint128.Mul64x64Add(&z[3], aa1, s2)

	uint128.Mul64x64(&z[4], aa0, s4)
	uint128.Mul64x64Add(&z[4], aa1, s3)
	uint128.Mul64x64Add(&z[4], s2, s2)

	uint128.Mul64x64(&z[5], aa1, s4)
	uint128.Mul64x64Add(&z[5], aa2, s3)

	uint128.Mul64x64(&z[6], aa2, s4)
	uint128.Mul64x64Add(&z[6], s3, s3)

	uint128.Mul64x64(&z[7], aa3, s4)

	uint128.Mul64x64(&z[8], s4, s4)

	return z
}

// scalarMulInternal computes `a * b`.
func scalarMulInternal(a, b *unpackedScalar) [9]uint128.Uint128 {
	var z [9]uint128.Uint128

	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]
	b0, b1, b2, b3, b4 := b[0], b[1], b[2], b[3], b[4]

	uint128.Mul64x64(&z[0], a0, b0)

	uint128.Mul64x64(&z[1], a0, b1)
	uint128.Mul64x64Add(&z[1], a1, b0)

	uint128.Mul64x64(&z[2], a0, b2)
	uint128.Mul64x64Add(&z[2], a1, b1)
	uint128.Mul64x64Add(&z[2], a2, b0)

	uint128.Mul64x64(&z[3], a0, b3)
	uint128.Mul64x64Add(&z[3], a1, b2)
	uint128.Mul64x64Add(&z[3], a2, b1)
	uint128.Mul64x64Add(&z[3], a3, b0)

	uint128.Mul64x64(&z[4], a0, b4)
	uint128.Mul64x64Add(&z[4], a1, b3)
	uint128.Mul64x64Add(&z[4], a2, b2)
	uint128.Mul64x64Add(&z[4], a3, b1)
	uint128.Mul64x64Add(&z[4], a4, b0)

	uint128.Mul64x64(&z[5], a1, b4)
	uint128.Mul64x64Add(&z[5], a2, b3)
	uint128.Mul64x64Add(&z[5], a3, b2)
	uint128.Mul64x64Add(&z[5], a4, b1)

	uint128.Mul64x64(&z[6], a2, b4)
	uint128.Mul64x64Add(&z[6], a3, b3)
	uint128.Mul64x64Add(&z[6], a4, b2)

	uint128.Mul64x64(&z[7], a3, b4)
	uint128.Mul64x64Add(&z[7], a4, b3)

	uint128.Mul64x64(&z[8], a4, b4)

	return z
}
