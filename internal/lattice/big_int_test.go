// Copyright (c) 2020 Jack Grigg
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

package lattice

import (
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

func TestInt512(t *testing.T) {
	t.Run("Cmp", testInt512Cmp)
	t.Run("BitLen", testInt512BitLen)
	t.Run("Shl", testInt512Shl)
	t.Run("Mul", testInt512Mul)
}

func testInt512Cmp(t *testing.T) {
	zero := i512Zero
	one := i512One
	negOne := (&int512{}).Sub(zero, one)
	ellSq := ellSquared()
	negEllSq := (&int512{}).Sub(zero, ellSq)

	if c := zero.Cmp(one); c != -1 {
		t.Fatalf("0.Cmp(1) != -1 (Got: %v)", c)
	}
	if c := one.Cmp(ellSq); c != -1 {
		t.Fatalf("1.Cmp(l^2) != -1 (Got: %v)", c)
	}
	if c := zero.Cmp(negOne); c != 1 {
		t.Fatalf("0.Cmp(-1) != 1 (Got: %v)", c)
	}
	if c := negOne.Cmp(one); c != -1 {
		t.Fatalf("-1.Cmp(1) != -1 (Got: %v)", c)
	}
	if c := negOne.Cmp(negEllSq); c != 1 {
		t.Fatalf("-1.Cmp(-l^2) != 1 (Got: %v)", c)
	}
	if c := one.Cmp(negEllSq); c != 1 {
		t.Fatalf("1.Cmp(-l^2) != 1 (Got: %v)", c)
	}
	if c := one.Cmp(one); c != 0 {
		t.Fatalf("1.Cmp(1) != 0 (Got: %v)", c)
	}
}

func testInt512BitLen(t *testing.T) {
	zero := i512Zero
	one := i512One
	negOne := (&int512{}).Sub(zero, one)
	ellSq := ellSquared()
	negEllSq := (&int512{}).Sub(zero, ellSq)

	if l := zero.BitLen(); l != 0 {
		t.Fatalf("BitLen(0) != 0 (Got: %v)", l)
	}
	if l := one.BitLen(); l != 1 {
		t.Fatalf("BitLen(1) != 1 (Got: %v)", l)
	}
	if l := negOne.BitLen(); l != 0 {
		t.Fatalf("BitLen(-1) != 0 (Got: %v)", l)
	}
	if l := ellSq.BitLen(); l != 505 {
		t.Fatalf("BitLen(l^2) != 505 (Got: %v)", l)
	}
	if l := negEllSq.BitLen(); l != 505 {
		t.Fatalf("BitLen(-l^2) != 505 (Got: %v)", l)
	}
}

func testInt512Shl(t *testing.T) {
	shl := func(x *int512, s uint) *int512 {
		return (&int512{}).Shl(x, s)
	}

	for i, tc := range []struct {
		x, e *int512
		s    uint
	}{
		{
			x: i512One,
			e: newInt512(2, 0, 0, 0, 0, 0, 0, 0),
			s: 1,
		},
		{
			x: newInt512(
				0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000,
				0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000,
			),
			e: newInt512(
				0xffffffffff000000, 0x0000000000ffffff, 0xffffffffff000000, 0x0000000000ffffff,
				0xffffffffff000000, 0x0000000000ffffff, 0xffffffffff000000, 0x0000000000ffffff,
			),
			s: 24,
		},
		{
			x: newInt512(
				0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x01ffffffffffffff,
			),
			e: newInt512(
				0xffff000000000000, 0x0000ffffffffffff, 0x0000000000000000, 0x0000000000000000,
				0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xffff000000000000,
			),
			s: 48,
		},
		{
			x: newInt512(
				0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000,
				0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000,
			),
			e: newInt512(
				0x0000000000000000, 0xffff000000000000, 0x0000ffffffffffff, 0xffff000000000000,
				0x0000ffffffffffff, 0xffff000000000000, 0x0000ffffffffffff, 0xffff000000000000,
			),
			s: 112,
		},
	} {
		v := shl(tc.x, tc.s)
		if *v != *tc.e {
			t.Fatalf("[%d]: %v << %d != %v (Got: %v)", i, tc.x, tc.s, tc.e, v)
		}
	}
}

func testInt512Mul(t *testing.T) {
	ellSq := ellSquared()
	shouldBeEllSq := (&int512{}).Mul(scalar.BASEPOINT_ORDER, scalar.BASEPOINT_ORDER)

	if *shouldBeEllSq != *ellSq {
		t.Fatalf("Mul(l, l) != l^2 (Got: %v)", shouldBeEllSq)
	}
}
