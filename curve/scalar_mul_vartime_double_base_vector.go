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

// +build amd64,!purego,!forcenoasm,!force32bit

package curve

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

func edwardsDoubleScalarMulBasepointVartimeVector(out *EdwardsPoint, a *scalar.Scalar, A *EdwardsPoint, b *scalar.Scalar) {
	aNaf := a.NonAdjacentForm(5)
	bNaf := b.NonAdjacentForm(8)

	// Find the starting index.
	var i int
	for j := 255; j >= 0; j-- {
		i = j
		if aNaf[i] != 0 || bNaf[i] != 0 {
			break
		}
	}

	tableA := newCachedPointNafLookupTable(A)
	tableB := &constVECTOR_ODD_MULTIPLES_OF_BASEPOINT

	var q extendedPoint
	q.identity()

	for {
		q.double()

		if aNaf[i] > 0 {
			pt := tableA.lookup(uint8(aNaf[i]))
			q.addExtendedCached(&q, &pt)
		} else if aNaf[i] < 0 {
			pt := tableA.lookup(uint8(-aNaf[i]))
			q.subExtendedCached(&q, &pt)
		}

		if bNaf[i] > 0 {
			pt := tableB.lookup(uint8(bNaf[i]))
			q.addExtendedCached(&q, &pt)
		} else if bNaf[i] < 0 {
			pt := tableB.lookup(uint8(-bNaf[i]))
			q.subExtendedCached(&q, &pt)
		}

		if i == 0 {
			break
		}
		i--
	}

	out.fromExtended(&q)
}
