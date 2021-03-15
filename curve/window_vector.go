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

// +build amd64,!purego,!forcenoasm,!force32bit

package curve

//go:noescape
func lookupCached(table *cachedPointLookupTable, out *cachedPoint, xabs uint8)

type cachedPointLookupTable [8]cachedPoint

func (tbl *cachedPointLookupTable) Lookup(x int8) cachedPoint {
	// Compute xabs = |x|
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	// Set t = 0 * P = identity
	var t cachedPoint
	lookupCached(tbl, &t, xabs)
	// Now t == |x| * P.

	negMask := int(byte(xmask & 1))
	t.ConditionalNegate(negMask)
	// Now t == x * P.

	return t
}

func newCachedPointLookupTable(ep *EdwardsPoint) cachedPointLookupTable {
	var (
		epExtended extendedPoint
		epCached   cachedPoint
	)

	epCached.SetExtended(epExtended.SetEdwards(ep))

	points := [8]cachedPoint{
		epCached, epCached, epCached, epCached,
		epCached, epCached, epCached, epCached,
	}
	for i := 0; i < 7; i++ {
		var tmp extendedPoint
		points[i+1].SetExtended(tmp.AddExtendedCached(&epExtended, &points[i]))
	}

	return cachedPointLookupTable(points)
}

// Holds odd multiples 1A, 3A, ..., 15A of a point A.
type cachedPointNafLookupTable [8]cachedPoint

func (tbl *cachedPointNafLookupTable) Lookup(x uint8) *cachedPoint {
	return &tbl[x/2]
}

func newCachedPointNafLookupTable(ep *EdwardsPoint) cachedPointNafLookupTable {
	var (
		epExtended extendedPoint
		epCached   cachedPoint
		A2         extendedPoint
	)

	epCached.SetExtended(epExtended.SetEdwards(ep))

	Ai := [8]cachedPoint{
		epCached, epCached, epCached, epCached,
		epCached, epCached, epCached, epCached,
	}

	A2.Double(&epExtended)
	for i := 0; i < 7; i++ {
		var tmp extendedPoint
		Ai[i+1].SetExtended(tmp.AddExtendedCached(&A2, &Ai[i]))
	}

	return cachedPointNafLookupTable(Ai)
}

// Holds stuff up to 8.
type cachedPointNafLookupTable8 [64]cachedPoint

func (tbl *cachedPointNafLookupTable8) Lookup(x uint8) *cachedPoint {
	return &tbl[x/2]
}

func newCachedPointNafLookupTable8(ep *EdwardsPoint) cachedPointNafLookupTable8 { //nolint:unused,deadcode
	var (
		epExtended extendedPoint
		epCached   cachedPoint
		A2         extendedPoint
	)

	epCached.SetExtended(epExtended.SetEdwards(ep))

	var Ai [64]cachedPoint
	for i := range Ai {
		Ai[i] = epCached
	}

	A2.Double(&epExtended)
	for i := 0; i < 63; i++ {
		var tmp extendedPoint
		Ai[i+1].SetExtended(tmp.AddExtendedCached(&A2, &Ai[i]))
	}

	return cachedPointNafLookupTable8(Ai)
}

func newCachedPointShl128NafLookupTable8(ep *EdwardsPoint) cachedPointNafLookupTable8 { //nolint:unused,deadcode
	table := newCachedPointNafLookupTable8(ep)
	for i, cp := range table {
		var tmp extendedPoint
		tmp.AddExtendedCached(tmp.Identity(), &cp)
		tmp.MulByPow2(&tmp, 128)
		table[i].SetExtended(&tmp)
	}

	return table
}
