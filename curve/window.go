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

// This has a mountain of duplicated code because having generics is too
// much to ask for currently.

type projectiveNielsPointLookupTable [8]projectiveNielsPoint

func (tbl *projectiveNielsPointLookupTable) lookup(x int8) projectiveNielsPoint {
	// Compute xabs = |x|
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	// Set t = 0 * P = identity
	var t projectiveNielsPoint
	lookupProjectiveNiels(tbl, &t, xabs)
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

// Note: Unlike curve25519-dalek, the table uses the packed format as the
// internal representation, as 96-byte entries are significantly easier
// to manipulate with vector instructions.
type packedAffineNielsPointLookupTable [8][96]byte

func (tbl *packedAffineNielsPointLookupTable) lookup(x int8) affineNielsPoint {
	// Compute xabs = |x|
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	// Set t = 0 * P = identity
	var tPacked [96]byte
	lookupAffineNiels(tbl, &tPacked, xabs)
	// Now t == |x| * P.

	// Unpack t.
	var t affineNielsPoint
	_ = t.y_plus_x.FromBytes(tPacked[0:32])
	_ = t.y_minus_x.FromBytes(tPacked[32:64])
	_ = t.xy2d.FromBytes(tPacked[64:96])

	negMask := int(byte(xmask & 1))
	t.conditionalNegate(negMask)
	// Now t == x * P.

	return t
}

func newPackedAffineNielsPointLookupTable(ep *EdwardsPoint) packedAffineNielsPointLookupTable {
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

	// Pack the table.  At this point, `points` is equivalent to the table
	// used by curve25519-dalek.
	var tbl packedAffineNielsPointLookupTable
	for i, point := range points {
		_ = point.y_plus_x.ToBytes(tbl[i][0:32])
		_ = point.y_minus_x.ToBytes(tbl[i][32:64])
		_ = point.xy2d.ToBytes(tbl[i][64:96])
	}

	return tbl
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
