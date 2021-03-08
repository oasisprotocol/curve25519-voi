// Copyright (c) 2017 George Tankersley. All rights reserved.
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

package field

import (
	"math/bits"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// quickCheckConfig will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig = &quick.Config{MaxCountScale: 1 << 10}

func generateFieldElement(rand *rand.Rand) FieldElement {
	// Generation strategy: generate random limb values of [52, 51, 51, 51, 51]
	// bits, like the ones returned by lightReduce.
	const low_52_bit_mask = (1 << 52) - 1
	return NewFieldElement51(
		rand.Uint64()&low_52_bit_mask,
		rand.Uint64()&low_51_bit_mask,
		rand.Uint64()&low_51_bit_mask,
		rand.Uint64()&low_51_bit_mask,
		rand.Uint64()&low_51_bit_mask,
	)
}

// weirdLimbs can be combined to generate a range of edge-case field elements.
// 0 and -1 are intentionally more weighted, as they combine well.
var (
	weirdLimbs51 = []uint64{
		0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
	}
	weirdLimbs52 = []uint64{
		0, 0, 0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		1 << 51,
		(1 << 51) + 1,
		(1 << 52) - 19,
		(1 << 52) - 1,
	}
)

func generateWeirdFieldElement(rand *rand.Rand) FieldElement {
	return NewFieldElement51(
		weirdLimbs52[rand.Intn(len(weirdLimbs52))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
	)
}

func (x FieldElement) Generate(rand *rand.Rand, size int) reflect.Value {
	if rand.Intn(2) == 0 {
		return reflect.ValueOf(generateWeirdFieldElement(rand))
	}
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInAsmBounds returns whether the element is within the expected bit
// size bounds after a light reduction, based on the behavior of
// the amd64 specific assembly multiply/pow2k routines.
func isInAsmBounds(x *FieldElement) bool {
	return bits.Len64(x.inner[0]) <= 52 &&
		bits.Len64(x.inner[1]) <= 51 &&
		bits.Len64(x.inner[2]) <= 51 &&
		bits.Len64(x.inner[3]) <= 51 &&
		bits.Len64(x.inner[4]) <= 51
}

func TestFeMulAsm(t *testing.T) {
	t.Run("FeMul/mul", func(t *testing.T) {
		testFeMul(t)
	})
	t.Run("FePow2k/mul", func(t *testing.T) {
		testFePow2k(t)
	})
}

func testFeMul(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z FieldElement) bool {
		var t1, t2, t3, t1Asm, t2Asm, t3Asm FieldElement

		// Note: The coefficients are allowed to grow up to 2^54
		// between reductions, which is what the generic mul
		// implementation does.
		//
		// The assembly reduces to 2^[51,52], which is different,
		// but still correct as the shorter coefficients will not
		// cause overflows.
		//
		// Attempts were made to make the assembly match the
		// generic code exactly, but it ended up being slightly
		// slower.

		// Compute t1 = (x+y)*z
		t1.Add(&x, &y)
		feMul(&t1Asm, &t1, &z)
		feMulGeneric(&t1, &t1, &z)
		if t1.Equal(&t1Asm) != 1 || !isInAsmBounds(&t1Asm) {
			return false
		}

		// Compute t2 = x*z + y*z
		feMul(&t2Asm, &x, &z)
		feMul(&t3Asm, &y, &z)
		feMulGeneric(&t2, &x, &z)
		feMulGeneric(&t3, &y, &z)
		if t2.Equal(&t2Asm) != 1 || !isInAsmBounds(&t2Asm) {
			return false
		}
		if t3.Equal(&t3Asm) != 1 || !isInAsmBounds(&t3Asm) {
			return false
		}
		t2.Add(&t2, &t3)
		t2Asm.Add(&t2Asm, &t3Asm)

		return t1.Equal(&t2) == 1 && t2Asm.Equal(&t1) == 1 && t1Asm.Equal(&t2) == 1
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func testFePow2k(t *testing.T) {
	a, ap16 := testConstants["A"], testConstants["AP16"]

	var shouldBeAp16 FieldElement
	fePow2k(&shouldBeAp16, a, 4)

	if shouldBeAp16.Equal(ap16) != 1 {
		t.Fatalf("a ^ (2^4) != ap16 (Got: %v)", shouldBeAp16)
	}
}
