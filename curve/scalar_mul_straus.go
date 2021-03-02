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

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

func edwardsMultiscalarMulStrausGeneric(out *EdwardsPoint, scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	lookupTables := make([]projectiveNielsPointLookupTable, 0, len(points))
	for _, point := range points {
		lookupTables = append(lookupTables, newProjectiveNielsPointLookupTable(point))
	}

	// TODO: In theory this should be sanitized.
	scalarDigitsVec := make([][64]int8, 0, len(scalars))
	for _, scalar := range scalars {
		scalarDigitsVec = append(scalarDigitsVec, scalar.ToRadix16())
	}

	out.Identity()

	var sum completedPoint
	for i := 63; i >= 0; i-- {
		out.mulByPow2(out, 4)
		for j := 0; j < len(points); j++ {
			// R_i = s_{i,j} * P_i
			R_i := lookupTables[j].Lookup(scalarDigitsVec[j][i])
			// Q = Q + R_i
			out.setCompleted(sum.AddEdwardsProjectiveNiels(out, &R_i))
		}
	}

	return out
}

func edwardsMultiscalarMulStrausVartimeGeneric(out *EdwardsPoint, scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	lookupTables := make([]projectiveNielsPointNafLookupTable, 0, len(points))
	for _, point := range points {
		lookupTables = append(lookupTables, newProjectiveNielsPointNafLookupTable(point))
	}

	nafs := make([][256]int8, 0, len(scalars))
	for _, scalar := range scalars {
		nafs = append(nafs, scalar.NonAdjacentForm(5))
	}

	var r projectivePoint
	r.Identity()

	var t completedPoint
	for i := 255; i >= 0; i-- {
		t.Double(&r)

		for j := 0; j < len(points); j++ {
			naf_i := nafs[j][i]
			if naf_i > 0 {
				t.AddCompletedProjectiveNiels(&t, lookupTables[j].lookup(uint8(naf_i)))
			} else if naf_i < 0 {
				t.SubCompletedProjectiveNiels(&t, lookupTables[j].lookup(uint8(-naf_i)))
			}
		}

		r.SetCompleted(&t)
	}

	return out.setProjective(&r)
}
