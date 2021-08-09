// Copyright (c) 2016-2019 isis agora lovecruft. All rights reserved.
// Copyright (c) 2016-2019 Henry de Valence. All rights reserved.
// Copyright (c) 2020-2021 Oasis Labs Inc. All rights reserved.
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

//go:build (386 || arm || mips || mipsle || mips64le || mips64 || force32bit) && !force64bit
// +build 386 arm mips mipsle mips64le mips64 force32bit
// +build !force64bit

package field

import "github.com/oasisprotocol/curve25519-voi/internal/subtle"

// ConditionalSelect sets the field element to a iff choice == 0 and
// b iff choice == 1.
func (fe *Element) ConditionalSelect(a, b *Element, choice int) {
	fe.inner[0] = subtle.ConstantTimeSelectUint32(choice, b.inner[0], a.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint32(choice, b.inner[1], a.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint32(choice, b.inner[2], a.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint32(choice, b.inner[3], a.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint32(choice, b.inner[4], a.inner[4])
	fe.inner[5] = subtle.ConstantTimeSelectUint32(choice, b.inner[5], a.inner[5])
	fe.inner[6] = subtle.ConstantTimeSelectUint32(choice, b.inner[6], a.inner[6])
	fe.inner[7] = subtle.ConstantTimeSelectUint32(choice, b.inner[7], a.inner[7])
	fe.inner[8] = subtle.ConstantTimeSelectUint32(choice, b.inner[8], a.inner[8])
	fe.inner[9] = subtle.ConstantTimeSelectUint32(choice, b.inner[9], a.inner[9])
}

// ConditionalSwap conditionally swaps the field elements according to choice.
func (fe *Element) ConditionalSwap(other *Element, choice int) {
	subtle.ConstantTimeSwapUint32(choice, &other.inner[0], &fe.inner[0])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[1], &fe.inner[1])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[2], &fe.inner[2])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[3], &fe.inner[3])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[4], &fe.inner[4])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[5], &fe.inner[5])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[6], &fe.inner[6])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[7], &fe.inner[7])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[8], &fe.inner[8])
	subtle.ConstantTimeSwapUint32(choice, &other.inner[9], &fe.inner[9])
}

// ConditionalAssign conditionally assigns the field element according to choice.
func (fe *Element) ConditionalAssign(other *Element, choice int) {
	fe.inner[0] = subtle.ConstantTimeSelectUint32(choice, other.inner[0], fe.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint32(choice, other.inner[1], fe.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint32(choice, other.inner[2], fe.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint32(choice, other.inner[3], fe.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint32(choice, other.inner[4], fe.inner[4])
	fe.inner[5] = subtle.ConstantTimeSelectUint32(choice, other.inner[5], fe.inner[5])
	fe.inner[6] = subtle.ConstantTimeSelectUint32(choice, other.inner[6], fe.inner[6])
	fe.inner[7] = subtle.ConstantTimeSelectUint32(choice, other.inner[7], fe.inner[7])
	fe.inner[8] = subtle.ConstantTimeSelectUint32(choice, other.inner[8], fe.inner[8])
	fe.inner[9] = subtle.ConstantTimeSelectUint32(choice, other.inner[9], fe.inner[9])
}

// One sets fe to one, and returns fe.
func (fe *Element) One() *Element {
	*fe = NewElement2625(1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	return fe
}

// MinusOne sets fe to -1, and returns fe.
func (fe *Element) MinusOne() *Element {
	*fe = NewElement2625(
		0x3ffffec, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff,
		0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
	)
	return fe
}

// NewElement2625 constructs a field element from its raw component limbs.
func NewElement2625(l0, l1, l2, l3, l4, l5, l6, l7, l8, l9 uint32) Element {
	return Element{
		inner: [10]uint32{
			l0, l1, l2, l3, l4, l5, l6, l7, l8, l9,
		},
	}
}
