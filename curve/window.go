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

package curve

import "github.com/oasisprotocol/curve25519-voi/internal/subtle"

// This has a mountain of duplicated code because having generics is too
// much to ask for currently.

type projectiveNielsPointLookupTable [8]projectiveNielsPoint

func (tbl *projectiveNielsPointLookupTable) lookup(x int8) projectiveNielsPoint {
	// Compute xabx = |x|
	xmask := x >> 7
	xabs := (x + xmask) ^ xmask

	// Set t = 0 * P = identity
	var t projectiveNielsPoint
	t.identity()
	for j := 1; j < 9; j++ {
		// Copy `points[j-1] == j*P` onto `t` in constant time if `|x| == j`.
		c := subtle.ConstantTimeCompareByte(byte(xabs), byte(j))
		t.conditionalAssign(&tbl[j-1], c)
	}
	// Now t == |x| * P.

	negMask := int(byte(xmask & 1))
	t.conditionalNegate(negMask)
	// Now t == x * P.

	return t
}

func newProjectiveNielsPointLookupTable(ep *EdwardsPoint) projectiveNielsPointLookupTable {
	var epPNiels projectiveNielsPoint
	epPNiels.fromEdwards(ep)

	points := [8]projectiveNielsPoint{
		epPNiels, epPNiels, epPNiels, epPNiels,
		epPNiels, epPNiels, epPNiels, epPNiels,
	}
	for j := 0; j < 7; j++ {
		var (
			tmp  completedPoint
			tmp2 EdwardsPoint
		)
		tmp.addEdwardsProjectiveNiels(ep, &points[j])
		tmp2.fromCompleted(&tmp)
		points[j+1].fromEdwards(&tmp2)
	}

	return projectiveNielsPointLookupTable(points)
}

type affineNielsPointLookupTable [8]affineNielsPoint

func (tbl *affineNielsPointLookupTable) lookup(x int8) affineNielsPoint {
	// Compute xabx = |x|
	xmask := x >> 7
	xabs := (x + xmask) ^ xmask

	// Set t = 0 * P = identity
	var t affineNielsPoint
	t.identity()
	for j := 1; j < 9; j++ {
		// Copy `points[j-1] == j*P` onto `t` in constant time if `|x| == j`.
		c := subtle.ConstantTimeCompareByte(byte(xabs), byte(j))
		t.conditionalAssign(&tbl[j-1], c)
	}
	// Now t == |x| * P.

	negMask := int(byte(xmask & 1))
	t.conditionalNegate(negMask)
	// Now t == x * P.

	return t
}

func newAffineNielsPointLookupTable(ep *EdwardsPoint) affineNielsPointLookupTable {
	var epANiels affineNielsPoint
	epANiels.fromEdwards(ep)

	points := [8]affineNielsPoint{
		epANiels, epANiels, epANiels, epANiels,
		epANiels, epANiels, epANiels, epANiels,
	}
	for j := 0; j < 7; j++ {
		var (
			tmp  completedPoint
			tmp2 EdwardsPoint
		)
		tmp.addEdwardsAffineNiels(ep, &points[j])
		tmp2.fromCompleted(&tmp)
		points[j+1].fromEdwards(&tmp2)
	}

	return affineNielsPointLookupTable(points)
}

// Holds odd multiples 1A, 3A, ..., 15A of a point A.
type projectiveNielsPointNafLookupTable [8]projectiveNielsPoint

func (tbl *projectiveNielsPointNafLookupTable) lookup(x uint8) projectiveNielsPoint {
	return tbl[x/2]
}

func newProjectiveNielsPointNafLookupTable(ep *EdwardsPoint) projectiveNielsPointNafLookupTable {
	var epPNiels projectiveNielsPoint
	epPNiels.fromEdwards(ep)

	Ai := [8]projectiveNielsPoint{
		epPNiels, epPNiels, epPNiels, epPNiels,
		epPNiels, epPNiels, epPNiels, epPNiels,
	}

	A2 := *ep
	A2.double()
	for i := 0; i < 7; i++ {
		var (
			tmp  completedPoint
			tmp2 EdwardsPoint
		)
		tmp.addEdwardsProjectiveNiels(&A2, &Ai[i])
		tmp2.fromCompleted(&tmp)
		Ai[i+1].fromEdwards(&tmp2)
	}

	return projectiveNielsPointNafLookupTable(Ai)
}

// Holds stuff up to 8.
type affineNielsPointNafLookupTable [64]affineNielsPoint

func (tbl *affineNielsPointNafLookupTable) lookup(x uint8) affineNielsPoint {
	return tbl[x/2]
}
