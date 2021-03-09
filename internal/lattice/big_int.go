// Copyright (c) 2020 Jack Grigg.  All rights reserved.
// Copyright (c) 2021 Oasis Labs Inc.  All rights reserved.
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

package lattice

import (
	"encoding/binary"
	"math/bits"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

var (
	i512Zero = &int512{}
	i512One  = newInt512(1, 0, 0, 0, 0, 0, 0, 0)
)

// int512 represents a signed two's complement 512-bit integer in eight
// 64-bit limbs.
type int512 [8]uint64

// IsNegative returns `true` if the sign bit is set.
func (x *int512) IsNegative() bool {
	return x[7]>>63 != 0
}

// BitLen returns the minimal size (in bits) of the binary representation
// of this value, in two's complement, excluding the sign bit.
func (x *int512) BitLen() uint {
	// The implementation starts with two observations:
	// - In two's complement, positive integers are padded above the most significant
	//   bit with 0-bits, and negative integers are padded above the MSB with 1-bits.
	// - We can efficiently count the number of leading zeroes in any limb.

	// Create a mask from the sign bit that matches the padding:
	// - All zeroes if positive.
	// - All ones if positive.
	signMask := uint64(-(int64(x[7] >> 63)))

	for i := 7; i >= 0; i-- {
		w := x[i]

		// Find the most significant limb that does not match the mask (and therefore
		// contains the most significant bit).
		if w == signMask {
			continue
		}

		// XOR the limb with the mask, resulting in a word that has leading zeroes
		// followed by the most significant bit as a 1.
		w ^= signMask

		// Compute the position of the most significant bit.
		return uint(i*int64Size + bits.Len64(w))
	}

	// If all limbs were padding, the bit length is zero.
	return 0
}

// Mul sets `x = a * b`, and returns x.
func (x *int512) Mul(a, b *scalar.Scalar) *int512 {
	toLimbs := func(s *scalar.Scalar) (l0, l1, l2, l3 uint64) {
		var b [scalar.ScalarSize]byte
		if err := s.ToBytes(b[:]); err != nil {
			panic("internal/lattice: failed to serialize scalar:" + err.Error())
		}

		l0 = binary.LittleEndian.Uint64(b[0:8])
		l1 = binary.LittleEndian.Uint64(b[8:16])
		l2 = binary.LittleEndian.Uint64(b[16:24])
		l3 = binary.LittleEndian.Uint64(b[24:32])

		return
	}

	mac := func(a, b, c, carry uint64) (uint64, uint64) {
		ret_hi, ret_lo := bits.Mul64(b, c)

		var carryOut uint64
		ret_lo, carryOut = bits.Add64(ret_lo, a, 0)
		ret_hi += carryOut

		ret_lo, carryOut = bits.Add64(ret_lo, carry, 0)
		ret_hi += carryOut

		return ret_lo, ret_hi
	}

	a0, a1, a2, a3 := toLimbs(a)
	b0, b1, b2, b3 := toLimbs(b)

	var w0, w1, w2, w3, w4, w5, w6, w7, carry uint64

	w0, carry = mac(0, a0, b0, 0)
	w1, carry = mac(0, a0, b1, carry)
	w2, carry = mac(0, a0, b2, carry)
	w3, w4 = mac(0, a0, b3, carry)

	w1, carry = mac(w1, a1, b0, 0)
	w2, carry = mac(w2, a1, b1, carry)
	w3, carry = mac(w3, a1, b2, carry)
	w4, w5 = mac(w4, a1, b3, carry)

	w2, carry = mac(w2, a2, b0, 0)
	w3, carry = mac(w3, a2, b1, carry)
	w4, carry = mac(w4, a2, b2, carry)
	w5, w6 = mac(w5, a2, b3, carry)

	w3, carry = mac(w3, a3, b0, 0)
	w4, carry = mac(w4, a3, b1, carry)
	w5, carry = mac(w5, a3, b2, carry)
	w6, w7 = mac(w6, a3, b3, carry)

	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7] = w0, w1, w2, w3, w4, w5, w6, w7

	return x
}

// Add sets `x = a + b`, and returns x.
func (x *int512) Add(a, b *int512) *int512 {
	var carry uint64
	x[0], carry = bits.Add64(a[0], b[0], carry)
	x[1], carry = bits.Add64(a[1], b[1], carry)
	x[2], carry = bits.Add64(a[2], b[2], carry)
	x[3], carry = bits.Add64(a[3], b[3], carry)
	x[4], carry = bits.Add64(a[4], b[4], carry)
	x[5], carry = bits.Add64(a[5], b[5], carry)
	x[6], carry = bits.Add64(a[6], b[6], carry)
	x[7], _ = bits.Add64(a[7], b[7], carry)
	return x
}

// Sub sets `x = a - b`, and returns x.
func (x *int512) Sub(a, b *int512) *int512 {
	var borrow uint64
	x[0], borrow = bits.Sub64(a[0], b[0], borrow)
	x[1], borrow = bits.Sub64(a[1], b[1], borrow)
	x[2], borrow = bits.Sub64(a[2], b[2], borrow)
	x[3], borrow = bits.Sub64(a[3], b[3], borrow)
	x[4], borrow = bits.Sub64(a[4], b[4], borrow)
	x[5], borrow = bits.Sub64(a[5], b[5], borrow)
	x[6], borrow = bits.Sub64(a[6], b[6], borrow)
	x[7], _ = bits.Sub64(a[7], b[7], borrow)
	return x
}

// Shl sets `x = a << s`, and returns x.
func (x *int512) Shl(a *int512, s uint) *int512 {
	k := s / int64Size
	switch k {
	case 0:
		*x = *a
		if s == 0 {
			// s = 0: x = a
			return x
		}
	case 1:
		*x = int512{0, a[0], a[1], a[2], a[3], a[4], a[5], a[6]}
	case 2:
		*x = int512{0, 0, a[0], a[1], a[2], a[3], a[4], a[5]}
	case 3:
		*x = int512{0, 0, 0, a[0], a[1], a[2], a[3], a[4]}
	case 4:
		*x = int512{0, 0, 0, 0, a[0], a[1], a[2], a[3]}
	case 5:
		*x = int512{0, 0, 0, 0, 0, a[0], a[1], a[2]}
	case 6:
		*x = int512{0, 0, 0, 0, 0, 0, a[0], a[1]}
	case 7:
		*x = int512{0, 0, 0, 0, 0, 0, 0, a[0]}
	default:
		// This should NEVER happen, but handle it anyway.
		*x = int512{}
		return x
	}
	s = s & 0x3f // k * 64 bits shifted as part of the copy, derive the remainder.

	var carry uint64
	switch k {
	case 0:
		x[0], carry = x[0]<<s|carry, x[0]>>(int64Size-s)
		fallthrough
	case 1:
		x[1], carry = x[1]<<s|carry, x[1]>>(int64Size-s)
		fallthrough
	case 2:
		x[2], carry = x[2]<<s|carry, x[2]>>(int64Size-s)
		fallthrough
	case 3:
		x[3], carry = x[3]<<s|carry, x[3]>>(int64Size-s)
		fallthrough
	case 4:
		x[4], carry = x[4]<<s|carry, x[4]>>(int64Size-s)
		fallthrough
	case 5:
		x[5], carry = x[5]<<s|carry, x[5]>>(int64Size-s)
		fallthrough
	case 6:
		x[6], carry = x[6]<<s|carry, x[6]>>(int64Size-s)
		fallthrough
	case 7:
		x[7], _ = x[7]<<s|carry, x[7]>>(int64Size-s)
	}

	return x
}

// Cmp compares x and y and returns `-1` if `x < y`, `0` if `x == y`, and
// `+1` if x > y.
func (x *int512) Cmp(y *int512) int {
	// If the signs differ, we can quickly determine ordering.
	xIsNeg, yIsNeg := x.IsNegative(), y.IsNegative()
	switch {
	case xIsNeg && !yIsNeg:
		return -1
	case !xIsNeg && yIsNeg:
		return 1
	}

	// Compare the integers ignoring sign. Because we use two's complement,
	// and the integers have the same sign, this is guaranteed to give the
	// correct result.
	for i := 7; i >= 0; i-- {
		switch {
		case y[i] > x[i]:
			return -1
		case x[i] > y[i]:
			return 1
		}
	}

	return 0
}

func newInt512(l0, l1, l2, l3, l4, l5, l6, l7 uint64) *int512 {
	return &int512{l0, l1, l2, l3, l4, l5, l6, l7}
}

func ellSquared() *int512 {
	return newInt512(
		0xe2edf685ab128969,
		0x680392762298a31d,
		0x3dceec73d217f5be,
		0xa1b399411b7c309a,
		0xcb024c634b9eba7d,
		0x029bdf3bd45ef39a,
		0x0000000000000000,
		0x0100000000000000,
	)
}
