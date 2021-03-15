// Copyright (c) 2016-2019 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
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

package curve

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

type edwardsBasepointTableGeneric [32]affineNielsPointLookupTable

func (tbl *edwardsBasepointTableGeneric) Basepoint() EdwardsPoint {
	// tbl[0].lookup(1) = 1*(16^2)^0*B
	// but as an `affineNielsPoint`, so convert to extended.
	aPt := tbl[0].Lookup(1)

	var ep EdwardsPoint
	ep.setAffineNiels(&aPt)

	return ep
}

func (tbl *edwardsBasepointTableGeneric) Mul(scalar *scalar.Scalar) EdwardsPoint {
	a := scalar.ToRadix16()

	var p EdwardsPoint
	p.Identity()

	var sum completedPoint
	for i := 1; i < 64; i = i + 2 {
		aPt := tbl[i/2].Lookup(a[i])
		p.setCompleted(sum.AddEdwardsAffineNiels(&p, &aPt))
	}

	p.mulByPow2(&p, 4)

	for i := 0; i < 64; i = i + 2 {
		aPt := tbl[i/2].Lookup(a[i])
		p.setCompleted(sum.AddEdwardsAffineNiels(&p, &aPt))
	}

	return p
}

func newEdwardsBasepointTableGeneric(basepoint *EdwardsPoint) *edwardsBasepointTableGeneric {
	var (
		table edwardsBasepointTableGeneric
		p     EdwardsPoint
	)

	p.Set(basepoint)
	for i := 0; i < 32; i++ {
		table[i] = newAffineNielsPointLookupTable(&p)
		p.mulByPow2(&p, 8)
	}

	return &table
}
