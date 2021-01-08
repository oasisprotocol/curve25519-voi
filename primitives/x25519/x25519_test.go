// Copyright (c) 2016 The Go Authors. All rights reserved.
// Copyright (c) 2019-2021 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package x25519

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	xcurve "golang.org/x/crypto/curve25519"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

const expectedHex = "89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a"

// result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times
var curved25519Expected = [32]byte{
	0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21,
	0x15, 0xe2, 0x3e, 0x84, 0x3c, 0x23, 0x2b, 0x5f,
	0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82, 0xd7, 0x93,
	0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04,
}

func TestScalarBaseMult(t *testing.T) {
	csk := [2][32]byte{
		{255},
	}

	for i := 0; i < 1024; i++ {
		ScalarBaseMult(&csk[(i&1)^1], &csk[i&1])
	}

	if !bytes.Equal(curved25519Expected[:], csk[0][:]) {
		t.Fatal("scalarmult ((|255| * basepoint) * basepoint)... 1024 did not match")
	}
}

func TestX25519(t *testing.T) {
	t.Run("voi", testX25519)
	if xcurveFaster {
		t.Run("voi/debugNoXcurve", func(t *testing.T) {
			debugNoXcurve = true
			defer func() {
				debugNoXcurve = false
			}()
			testX25519(t)
		})
	}
}

func testX25519(t *testing.T) {
	t.Run("Basepoint", testX25519Basepoint)
	t.Run("LowOrderPoints", testX25519LowOrderPoints)
	t.Run("TestVectors", func(t *testing.T) {
		testTestVectors(t, func(dst, scalar, point *[32]byte) {
			out, err := X25519(scalar[:], point[:])
			if err != nil {
				t.Fatal(err)
			}
			copy(dst[:], out)
		})
	})
}

func testX25519Basepoint(t *testing.T) {
	x := make([]byte, 32)
	x[0] = 1

	for i := 0; i < 200; i++ {
		var err error
		x, err = X25519(x, Basepoint)
		if err != nil {
			t.Fatal(err)
		}
	}

	result := fmt.Sprintf("%x", x)
	if result != expectedHex {
		t.Errorf("incorrect result: got %s, want %s", result, expectedHex)
	}
}

func testX25519LowOrderPoints(t *testing.T) {
	scalar := make([]byte, ScalarSize)
	if _, err := rand.Read(scalar); err != nil {
		t.Fatal(err)
	}
	for i, p := range lowOrderPoints {
		out, err := X25519(scalar, p)
		if err == nil {
			t.Errorf("%d: expected error, got nil", i)
		}
		if out != nil {
			t.Errorf("%d: expected nil output, got %x", i, out)
		}
	}
}

func testTestVectors(t *testing.T, scalarMult func(dst, scalar, point *[32]byte)) {
	for _, tv := range testVectors {
		var got [32]byte
		scalarMult(&got, &tv.In, &tv.Base)
		if !bytes.Equal(got[:], tv.Expect[:]) {
			t.Logf("    in = %x", tv.In)
			t.Logf("  base = %x", tv.Base)
			t.Logf("   got = %x", got)
			t.Logf("expect = %x", tv.Expect)
			t.Fail()
		}
	}
}

func TestScalarMult(t *testing.T) {
	t.Run("voi", testScalarMult)
	if xcurveFaster {
		t.Run("voi/debugNoXcurve", func(t *testing.T) {
			debugNoXcurve = true
			defer func() {
				debugNoXcurve = false
			}()
			testScalarMult(t)
		})
	}
}

func testScalarMult(t *testing.T) {
	t.Run("HighBitIgnored", testHighBitIgnored)
	t.Run("TestVectors", func(t *testing.T) {
		testTestVectors(t, ScalarMult)
	})
}

// testHighBitIgnored tests the following requirement in RFC 7748:
//
//	When receiving such an array, implementations of X25519 (but not X448) MUST
//	mask the most significant bit in the final byte.
//
// Regression test for issue #30095.
func testHighBitIgnored(t *testing.T) {
	var s, u [32]byte
	_, _ = rand.Read(s[:])
	_, _ = rand.Read(u[:])

	var hi0, hi1 [32]byte

	u[31] &= 0x7f
	ScalarMult(&hi0, &s, &u)

	u[31] |= 0x80
	ScalarMult(&hi1, &s, &u)

	if !bytes.Equal(hi0[:], hi1[:]) {
		t.Errorf("high bit of group point should not affect result")
	}
}

func TestX25519Conversion(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)

	xPrivate := EdPrivateKeyToX25519(private)
	xPublic, err := X25519(xPrivate, Basepoint)
	if err != nil {
		t.Errorf("X25519(xPrivate, Basepoint): %v", err)
	}

	xPublic2, ok := EdPublicKeyToX25519(public)
	if !ok {
		t.Errorf("EdPublicKeyToX25519(public): failed")
	}

	if !bytes.Equal(xPublic, xPublic2) {
		t.Errorf("Values didn't match: curve25519 produced %x, conversion produced %x", xPublic, xPublic2)
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	b.Run("voi", func(b *testing.B) { benchScalarBaseMult(b, ScalarBaseMult) })
	b.Run("xcrypto", func(b *testing.B) { benchScalarBaseMult(b, xcurve.ScalarBaseMult) })
}

func benchScalarBaseMult(b *testing.B, scalarBaseMult func(dst, scalar *[32]byte)) {
	var in, out [32]byte
	in[0] = 1

	b.SetBytes(32)
	for i := 0; i < b.N; i++ {
		scalarBaseMult(&out, &in)
	}
}

func BenchmarkScalarMult(b *testing.B) {
	b.Run("voi", func(b *testing.B) { benchScalarMult(b, ScalarMult) })
	if xcurveFaster {
		b.Run("voi/debugNoXcurve", func(b *testing.B) {
			debugNoXcurve = true
			defer func() {
				debugNoXcurve = false
			}()
			benchScalarMult(b, ScalarMult)
		})
	}
	b.Run("xcrypto", func(b *testing.B) {
		benchScalarMult(b, xcurve.ScalarMult) //nolint: staticcheck
	})
}

func benchScalarMult(b *testing.B, scalarMult func(dst, scalar, in *[32]byte)) {
	b.ResetTimer()

	var in, scalar, out [32]byte
	in[0] = 1
	scalar[0] = 1

	b.SetBytes(32)
	for i := 0; i < b.N; i++ {
		scalarMult(&out, &scalar, &in)
	}
}
