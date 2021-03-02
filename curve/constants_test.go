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

import (
	"testing"

	"github.com/oasisprotocol/curve25519-voi/internal/field"
)

func TestConstants(t *testing.T) {
	t.Run("Constants/EightTorsion", testConstantsEightTorsion)
	t.Run("Constants/FourTorsion", testConstantsFourTorsion)
	t.Run("Constants/TwoTorsion", testConstantsTwoTorsion)
	t.Run("Constants/SqrtAdMinusOne", testConstantsSqrtAdMinusOne)
	t.Run("Constants/D/VsRatio", testConstantsDVsRatio)
}

func testConstantsEightTorsion(t *testing.T) {
	for i, torsionPoint := range EIGHT_TORSION {
		var q EdwardsPoint
		q.mulByPow2(&torsionPoint, 3)
		if !q.debugIsValid() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(3).debugIsValid() != true", i)
		}
		if !q.IsIdentity() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(3).IsIdentity() != true", i)
		}
	}
}

func testConstantsFourTorsion(t *testing.T) {
	for i, torsionPoint := range EIGHT_TORSION {
		if i%2 != 0 {
			continue
		}
		var q EdwardsPoint
		q.mulByPow2(&torsionPoint, 2)
		if !q.debugIsValid() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(2).debugIsValid() != true", i)
		}
		if !q.IsIdentity() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(2).IsIdentity() != true", i)
		}
	}
}

func testConstantsTwoTorsion(t *testing.T) {
	for i, torsionPoint := range EIGHT_TORSION {
		if i%4 != 0 {
			continue
		}
		var q EdwardsPoint
		q.mulByPow2(&torsionPoint, 1)
		if !q.debugIsValid() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(1).debugIsValid() != true", i)
		}
		if !q.IsIdentity() {
			t.Fatalf("EIGHT_TORSION[%d].mulByPow2(1).IsIdentity() != true", i)
		}
	}
}

func testConstantsSqrtAdMinusOne(t *testing.T) {
	var a field.FieldElement
	a.MinusOne()

	var adMinusOne field.FieldElement
	adMinusOne.Mul(&a, &constEDWARDS_D)
	adMinusOne.Add(&adMinusOne, &a)

	var shouldBeAdMinusOne field.FieldElement
	shouldBeAdMinusOne.Square(&constSQRT_AD_MINUS_ONE)

	if shouldBeAdMinusOne.Equal(&adMinusOne) != 1 {
		t.Fatalf("should_be_ad_minus_one != ad_minus_one (Got: %v, %v)", shouldBeAdMinusOne, adMinusOne)
	}
}
