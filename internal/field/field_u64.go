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

package field

import (
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/internal/disalloweq"
	"github.com/oasisprotocol/curve25519-voi/internal/subtle"
	"github.com/oasisprotocol/curve25519-voi/internal/uint128"
)

const low_51_bit_mask uint64 = (1 << 51) - 1

// FieldElement represents an element of the field Z/(2^255 - 19).
type FieldElement struct {
	disalloweq.DisallowEqual //nolint:unused
	inner                    [5]uint64
}

// Add computes `a + b`.
func (fe *FieldElement) Add(a, b *FieldElement) {
	fe.inner[0] = a.inner[0] + b.inner[0]
	fe.inner[1] = a.inner[1] + b.inner[1]
	fe.inner[2] = a.inner[2] + b.inner[2]
	fe.inner[3] = a.inner[3] + b.inner[3]
	fe.inner[4] = a.inner[4] + b.inner[4]
}

// Sub computes `a - b`.
func (fe *FieldElement) Sub(a, b *FieldElement) {
	// To avoid underflow, first add a multiple of p.
	// Choose 16*p = p << 4 to be larger than 54-bit b.
	//
	// If we could statically track the bitlengths of the limbs
	// of every FieldElement, we could choose a multiple of p
	// just bigger than b and avoid having to do a reduction.

	fe.reduce(&[5]uint64{
		(a.inner[0] + 36028797018963664) - b.inner[0],
		(a.inner[1] + 36028797018963952) - b.inner[1],
		(a.inner[2] + 36028797018963952) - b.inner[2],
		(a.inner[3] + 36028797018963952) - b.inner[3],
		(a.inner[4] + 36028797018963952) - b.inner[4],
	})
}

// Mul computes `a * b`.
func (fe *FieldElement) Mul(a, b *FieldElement) {
	a0, a1, a2, a3, a4 := a.inner[0], a.inner[1], a.inner[2], a.inner[3], a.inner[4]
	b0, b1, b2, b3, b4 := b.inner[0], b.inner[1], b.inner[2], b.inner[3], b.inner[4]

	// Precondition: assume input limbs a[i], b[i] are bounded as
	//
	// a[i], b[i] < 2^(51 + b)
	//
	// where b is a real parameter measuring the "bit excess" of the limbs.

	// 64-bit precomputations to avoid 128-bit multiplications.
	//
	// This fits into a u64 whenever 51 + b + lg(19) < 64.
	//
	// Since 51 + b + lg(19) < 51 + 4.25 + b
	//                       = 55.25 + b,
	// this fits if b < 8.75.
	b1_19 := b1 * 19
	b2_19 := b2 * 19
	b3_19 := b3 * 19
	b4_19 := b4 * 19

	// Multiply to get 128-bit coefficients of output
	var c0, c1, c2, c3, c4 uint128.Uint128
	uint128.Mul64x64(&c0, a0, b0)
	uint128.Mul64x64Add(&c0, a4, b1_19)
	uint128.Mul64x64Add(&c0, a3, b2_19)
	uint128.Mul64x64Add(&c0, a2, b3_19)
	uint128.Mul64x64Add(&c0, a1, b4_19)

	uint128.Mul64x64(&c1, a1, b0)
	uint128.Mul64x64Add(&c1, a0, b1)
	uint128.Mul64x64Add(&c1, a4, b2_19)
	uint128.Mul64x64Add(&c1, a3, b3_19)
	uint128.Mul64x64Add(&c1, a2, b4_19)

	uint128.Mul64x64(&c2, a2, b0)
	uint128.Mul64x64Add(&c2, a1, b1)
	uint128.Mul64x64Add(&c2, a0, b2)
	uint128.Mul64x64Add(&c2, a4, b3_19)
	uint128.Mul64x64Add(&c2, a3, b4_19)

	uint128.Mul64x64(&c3, a3, b0)
	uint128.Mul64x64Add(&c3, a2, b1)
	uint128.Mul64x64Add(&c3, a1, b2)
	uint128.Mul64x64Add(&c3, a0, b3)
	uint128.Mul64x64Add(&c3, a4, b4_19)

	uint128.Mul64x64(&c4, a4, b0)
	uint128.Mul64x64Add(&c4, a3, b1)
	uint128.Mul64x64Add(&c4, a2, b2)
	uint128.Mul64x64Add(&c4, a1, b3)
	uint128.Mul64x64Add(&c4, a0, b4)

	// How big are the c[i]? We have
	//
	//    c[i] < 2^(102 + 2*b) * (1+i + (4-i)*19)
	//         < 2^(102 + lg(1 + 4*19) + 2*b)
	//         < 2^(108.27 + 2*b)
	//
	// The carry (c[i] >> 51) fits into a u64 when
	//    108.27 + 2*b - 51 < 64
	//    2*b < 6.73
	//    b < 3.365.
	//
	// So we require b < 3 to ensure this fits.

	uint128.Add64(&c1, uint128.ShrLo(&c0, 51))
	fe.inner[0] = uint128.Lo(&c0) & low_51_bit_mask

	uint128.Add64(&c2, uint128.ShrLo(&c1, 51))
	fe.inner[1] = uint128.Lo(&c1) & low_51_bit_mask

	uint128.Add64(&c3, uint128.ShrLo(&c2, 51))
	fe.inner[2] = uint128.Lo(&c2) & low_51_bit_mask

	uint128.Add64(&c4, uint128.ShrLo(&c3, 51))
	fe.inner[3] = uint128.Lo(&c3) & low_51_bit_mask

	carry := uint128.ShrLo(&c4, 51)
	fe.inner[4] = uint128.Lo(&c4) & low_51_bit_mask

	// To see that this does not overflow, we need fe[0] + carry * 19 < 2^64.
	//
	// c4 < a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + (carry from c3)
	//    < 5*(2^(51 + b) * 2^(51 + b)) + (carry from c3)
	//    < 2^(102 + 2*b + lg(5)) + 2^64.
	//
	// When b < 3 we get
	//
	// c4 < 2^110.33  so that carry < 2^59.33
	//
	// so that
	//
	// fe[0] + carry * 19 < 2^51 + 19 * 2^59.33 < 2^63.58
	//
	// and there is no overflow.
	fe.inner[0] = fe.inner[0] + carry*19

	// Now fe[1] < 2^51 + 2^(64 -51) = 2^51 + 2^13 < 2^(51 + epsilon).
	fe.inner[1] += fe.inner[0] >> 51
	fe.inner[0] &= low_51_bit_mask

	// Now fe[i] < 2^(51 + epsilon) for all i.
}

// Neg computes `-fe`.
func (fe *FieldElement) Neg() {
	// See commentary in the Sub impl.
	fe.reduce(&[5]uint64{
		36028797018963664 - fe.inner[0],
		36028797018963952 - fe.inner[1],
		36028797018963952 - fe.inner[2],
		36028797018963952 - fe.inner[3],
		36028797018963952 - fe.inner[4],
	})
}

// ConditionalSelect sets the field element to a iff choice == 0 and
// b iff choice == 1.
func (fe *FieldElement) ConditionalSelect(a, b *FieldElement, choice int) {
	fe.inner[0] = subtle.ConstantTimeSelectUint64(choice, b.inner[0], a.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint64(choice, b.inner[1], a.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint64(choice, b.inner[2], a.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint64(choice, b.inner[3], a.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint64(choice, b.inner[4], a.inner[4])
}

// ConditionalSwap conditionally swaps the field elements according to choice.
func (fe *FieldElement) ConditionalSwap(other *FieldElement, choice int) {
	subtle.ConstantTimeSwapUint64(choice, &other.inner[0], &fe.inner[0])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[1], &fe.inner[1])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[2], &fe.inner[2])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[3], &fe.inner[3])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[4], &fe.inner[4])
}

// ConditionalAssign conditionally assigns the field element according to choice.
func (fe *FieldElement) ConditionalAssign(other *FieldElement, choice int) {
	fe.inner[0] = subtle.ConstantTimeSelectUint64(choice, other.inner[0], fe.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint64(choice, other.inner[1], fe.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint64(choice, other.inner[2], fe.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint64(choice, other.inner[3], fe.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint64(choice, other.inner[4], fe.inner[4])
}

// One sets the field element to one.
func (fe *FieldElement) One() {
	*fe = NewFieldElement51(1, 0, 0, 0, 0)
}

// MinusOne sets the field element to -1.
func (fe *FieldElement) MinusOne() {
	*fe = NewFieldElement51(
		2251799813685228, 2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247,
	)
}

func (fe *FieldElement) reduce(limbs *[5]uint64) {
	// Since the input limbs are bounded by 2^64, the biggest
	// carry-out is bounded by 2^13.
	//
	// The biggest carry-in is c4 * 19, resulting in
	//
	// 2^51 + 19*2^13 < 2^51.0000000001
	//
	// Because we don't need to canonicalize, only to reduce the
	// limb sizes, it's OK to do a "weak reduction", where we
	// compute the carry-outs in parallel.

	c0 := limbs[0] >> 51
	c1 := limbs[1] >> 51
	c2 := limbs[2] >> 51
	c3 := limbs[3] >> 51
	c4 := limbs[4] >> 51

	limbs[0] &= low_51_bit_mask
	limbs[1] &= low_51_bit_mask
	limbs[2] &= low_51_bit_mask
	limbs[3] &= low_51_bit_mask
	limbs[4] &= low_51_bit_mask

	fe.inner[0] = limbs[0] + c4*19
	fe.inner[1] = limbs[1] + c0
	fe.inner[2] = limbs[2] + c1
	fe.inner[3] = limbs[3] + c2
	fe.inner[4] = limbs[4] + c3
}

// FromBytes loads a field element from the low 255 bits of a 256 bit input.
//
// WARNING: This function does not check that the input used the canonical
// representative.  It masks the high bit, but it will happily decode
// 2^255 - 18 to 1.  Applications that require a canonical encoding of
// every field element should decode, re-encode to the canonical encoding,
// and check that the input was canonical.
func (fe *FieldElement) FromBytes(in []byte) error {
	if len(in) != FieldElementSize {
		return fmt.Errorf("internal/field/u64: unexpected input size")
	}

	*fe = FieldElement{
		inner: [5]uint64{
			// load bits [  0, 64), no shift
			binary.LittleEndian.Uint64(in[0:]) & low_51_bit_mask,
			// load bits [ 48,112), shift to [ 51,112)
			(binary.LittleEndian.Uint64(in[6:]) >> 3) & low_51_bit_mask,
			// load bits [ 96,160), shift to [102,160)
			(binary.LittleEndian.Uint64(in[12:]) >> 6) & low_51_bit_mask,
			// load bits [152,216), shift to [153,216)
			(binary.LittleEndian.Uint64(in[19:]) >> 1) & low_51_bit_mask,
			// load bits [192,256), shift to [204,112)
			(binary.LittleEndian.Uint64(in[24:]) >> 12) & low_51_bit_mask,
		},
	}

	return nil
}

// ToBytes packs the field element into 32 bytes.  The encoding is canonical.
func (fe *FieldElement) ToBytes(out []byte) error {
	if len(out) != FieldElementSize {
		return fmt.Errorf("internal/field/u64: unexpected output size")
	}

	// Let h = limbs[0] + limbs[1]*2^51 + ... + limbs[4]*2^204.
	//
	// Write h = pq + r with 0 <= r < p.
	//
	// We want to compute r = h mod p.
	//
	// If h < 2*p = 2^256 - 38,
	// then q = 0 or 1,
	//
	// with q = 0 when h < p
	//  and q = 1 when h >= p.
	//
	// Notice that h >= p <==> h + 19 >= p + 19 <==> h + 19 >= 2^255.
	// Therefore q can be computed as the carry bit of h + 19.

	// First, reduce the limbs to ensure h < 2*p.
	var reduced FieldElement
	reduced.reduce(&fe.inner)
	l0, l1, l2, l3, l4 := reduced.inner[0], reduced.inner[1], reduced.inner[2], reduced.inner[3], reduced.inner[4]

	q := (l0 + 19) >> 51
	q = (l1 + q) >> 51
	q = (l2 + q) >> 51
	q = (l3 + q) >> 51
	q = (l4 + q) >> 51

	// Now we can compute r as r = h - pq = r - (2^255-19)q = r + 19q - 2^255q

	l0 += 19 * q

	// Now carry the result to compute r + 19q ...
	l1 += l0 >> 51
	l0 = l0 & low_51_bit_mask
	l2 += l1 >> 51
	l1 = l1 & low_51_bit_mask
	l3 += l2 >> 51
	l2 = l2 & low_51_bit_mask
	l4 += l3 >> 51
	l3 = l3 & low_51_bit_mask
	// ... but instead of carrying (l4 >> 51) = 2^255q
	// into another limb, discard it, subtracting the value
	l4 = l4 & low_51_bit_mask

	out[0] = byte(l0)
	out[1] = byte(l0 >> 8)
	out[2] = byte(l0 >> 16)
	out[3] = byte(l0 >> 24)
	out[4] = byte(l0 >> 32)
	out[5] = byte(l0 >> 40)
	out[6] = byte((l0 >> 48) | (l1 << 3))
	out[7] = byte(l1 >> 5)
	out[8] = byte(l1 >> 13)
	out[9] = byte(l1 >> 21)
	out[10] = byte(l1 >> 29)
	out[11] = byte(l1 >> 37)
	out[12] = byte((l1 >> 45) | (l2 << 6))
	out[13] = byte(l2 >> 2)
	out[14] = byte(l2 >> 10)
	out[15] = byte(l2 >> 18)
	out[16] = byte(l2 >> 26)
	out[17] = byte(l2 >> 34)
	out[18] = byte(l2 >> 42)
	out[19] = byte((l2 >> 50) | (l3 << 1))
	out[20] = byte(l3 >> 7)
	out[21] = byte(l3 >> 15)
	out[22] = byte(l3 >> 23)
	out[23] = byte(l3 >> 31)
	out[24] = byte(l3 >> 39)
	out[25] = byte((l3 >> 47) | (l4 << 4))
	out[26] = byte(l4 >> 4)
	out[27] = byte(l4 >> 12)
	out[28] = byte(l4 >> 20)
	out[29] = byte(l4 >> 28)
	out[30] = byte(l4 >> 36)
	out[31] = byte(l4 >> 44)

	return nil
}

// Pow2k computes `self^(2^k)`, given `k > 0`.
func (fe *FieldElement) Pow2k(k uint) {
	if k == 0 {
		panic("internal/field/u64: k out of bounds")
	}

	var c0, c1, c2, c3, c4 uint128.Uint128
	a0, a1, a2, a3, a4 := fe.inner[0], fe.inner[1], fe.inner[2], fe.inner[3], fe.inner[4]

	for {
		// Precondition: assume input limbs a[i] are bounded as
		//
		// a[i] < 2^(51 + b)
		//
		// where b is a real parameter measuring the "bit excess" of the limbs.

		// Precomputation: 64-bit multiply by 19.
		//
		// This fits into a u64 whenever 51 + b + lg(19) < 64.
		//
		// Since 51 + b + lg(19) < 51 + 4.25 + b
		//                       = 55.25 + b,
		// this fits if b < 8.75.
		a3_19 := 19 * a3
		a4_19 := 19 * a4

		// Multiply to get 128-bit coefficients of output.
		uint128.Mul64x64(&c0, a1, a4_19)
		uint128.Mul64x64Add(&c0, a2, a3_19)
		uint128.Add(&c0, &c0)
		uint128.Mul64x64Add(&c0, a0, a0)

		uint128.Mul64x64(&c1, a0, a1)
		uint128.Mul64x64Add(&c1, a2, a4_19)
		uint128.Add(&c1, &c1)
		uint128.Mul64x64Add(&c1, a3, a3_19)

		uint128.Mul64x64(&c2, a0, a2)
		uint128.Mul64x64Add(&c2, a4, a3_19)
		uint128.Add(&c2, &c2)
		uint128.Mul64x64Add(&c2, a1, a1)

		uint128.Mul64x64(&c3, a0, a3)
		uint128.Mul64x64Add(&c3, a1, a2)
		uint128.Add(&c3, &c3)
		uint128.Mul64x64Add(&c3, a4, a4_19)

		uint128.Mul64x64(&c4, a0, a4)
		uint128.Mul64x64Add(&c4, a1, a3)
		uint128.Add(&c4, &c4)
		uint128.Mul64x64Add(&c4, a2, a2)

		// Same bound as in multiply:
		//    c[i] < 2^(102 + 2*b) * (1+i + (4-i)*19)
		//         < 2^(102 + lg(1 + 4*19) + 2*b)
		//         < 2^(108.27 + 2*b)
		//
		// The carry (c[i] >> 51) fits into a u64 when
		//    108.27 + 2*b - 51 < 64
		//    2*b < 6.73
		//    b < 3.365.
		//
		// So we require b < 3 to ensure this fits.

		uint128.Add64(&c1, uint128.ShrLo(&c0, 51))
		a0 = uint128.Lo(&c0) & low_51_bit_mask

		uint128.Add64(&c2, uint128.ShrLo(&c1, 51))
		a1 = uint128.Lo(&c1) & low_51_bit_mask

		uint128.Add64(&c3, uint128.ShrLo(&c2, 51))
		a2 = uint128.Lo(&c2) & low_51_bit_mask

		uint128.Add64(&c4, uint128.ShrLo(&c3, 51))
		a3 = uint128.Lo(&c3) & low_51_bit_mask

		carry := uint128.ShrLo(&c4, 51)
		a4 = uint128.Lo(&c4) & low_51_bit_mask

		// To see that this does not overflow, we need a[0] + carry * 19 < 2^64.
		//
		// c4 < a2^2 + 2*a0*a4 + 2*a1*a3 + (carry from c3)
		//    < 2^(102 + 2*b + lg(5)) + 2^64.
		//
		// When b < 3 we get
		//
		// c4 < 2^110.33  so that carry < 2^59.33
		//
		// so that
		//
		// a[0] + carry * 19 < 2^51 + 19 * 2^59.33 < 2^63.58
		//
		// and there is no overflow.
		a0 = a0 + carry*19

		// Now a[1] < 2^51 + 2^(64 -51) = 2^51 + 2^13 < 2^(51 + epsilon).
		a1 += a0 >> 51
		a0 &= low_51_bit_mask

		// Now all a[i] < 2^(51 + epsilon) and a = self^(2^k).

		k--
		if k == 0 {
			break
		}
	}

	fe.inner[0], fe.inner[1], fe.inner[2], fe.inner[3], fe.inner[4] = a0, a1, a2, a3, a4
}

// Square computes `self^2`.
func (fe *FieldElement) Square() {
	fe.Pow2k(1)
}

// Square2 computes `2*self^2`.
func (fe *FieldElement) Square2() {
	fe.Pow2k(1)
	for i := 0; i < 5; i++ {
		fe.inner[i] *= 2
	}
}

// NewFieldElement51 constructs a field element from its raw component limbs.
func NewFieldElement51(l0, l1, l2, l3, l4 uint64) FieldElement {
	return FieldElement{
		inner: [5]uint64{
			l0, l1, l2, l3, l4,
		},
	}
}