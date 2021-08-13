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

//go:build (amd64 || arm64 || ppc64le || ppc64 || s390x || force64bit) && !force32bit
// +build amd64 arm64 ppc64le ppc64 s390x force64bit
// +build !force32bit

package field

import "github.com/oasisprotocol/curve25519-voi/internal/subtle"

// ConditionalSelect sets the field element to a iff choice == 0 and
// b iff choice == 1.
func (fe *Element) ConditionalSelect(a, b *Element, choice int) {
	// This would use fiat.Selectznz, but arg1 takes a fiat.uint1, which
	// is unexported, so the routine is useless.
	fe.inner[0] = subtle.ConstantTimeSelectUint64(choice, b.inner[0], a.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint64(choice, b.inner[1], a.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint64(choice, b.inner[2], a.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint64(choice, b.inner[3], a.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint64(choice, b.inner[4], a.inner[4])
}

// ConditionalSwap conditionally swaps the field elements according to choice.
func (fe *Element) ConditionalSwap(other *Element, choice int) {
	subtle.ConstantTimeSwapUint64(choice, &other.inner[0], &fe.inner[0])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[1], &fe.inner[1])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[2], &fe.inner[2])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[3], &fe.inner[3])
	subtle.ConstantTimeSwapUint64(choice, &other.inner[4], &fe.inner[4])
}

// ConditionalAssign conditionally assigns the field element according to choice.
func (fe *Element) ConditionalAssign(other *Element, choice int) {
	fe.inner[0] = subtle.ConstantTimeSelectUint64(choice, other.inner[0], fe.inner[0])
	fe.inner[1] = subtle.ConstantTimeSelectUint64(choice, other.inner[1], fe.inner[1])
	fe.inner[2] = subtle.ConstantTimeSelectUint64(choice, other.inner[2], fe.inner[2])
	fe.inner[3] = subtle.ConstantTimeSelectUint64(choice, other.inner[3], fe.inner[3])
	fe.inner[4] = subtle.ConstantTimeSelectUint64(choice, other.inner[4], fe.inner[4])
}

// One sets the fe to one, and returns fe.
func (fe *Element) One() *Element {
	*fe = NewElement51(1, 0, 0, 0, 0)
	return fe
}

// MinusOne sets fe to -1, and returns fe.
func (fe *Element) MinusOne() *Element {
	*fe = NewElement51(
		2251799813685228, 2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247,
	)
	return fe
}

// NewElement51 constructs a field element from its raw component limbs.
func NewElement51(l0, l1, l2, l3, l4 uint64) Element {
	return Element{
		inner: [5]uint64{
			l0, l1, l2, l3, l4,
		},
	}
}
