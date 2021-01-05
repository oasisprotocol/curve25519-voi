// Copyright (c) 2016 The Go Authors. All rights reserved.
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

// Package x25519 provides an implementation of the X25519 function, which
// performs scalar multiplication on the elliptic curve known as Curve25519.
// See RFC 7748.
package x25519

import (
	"crypto/subtle"
	"fmt"
	"runtime"

	xcurve "golang.org/x/crypto/curve25519"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

const (
	// ScalarSize is the size of the scalar input to X25519.
	ScalarSize = 32
	// PointSize is the size of the point input to X25519.
	PointSize = 32
)

// Basepoint is the canonical Curve25519 generator.
var Basepoint []byte

var (
	basePoint = [32]byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	xcurveFaster  bool
	debugNoXcurve bool
)

// ScalarMult sets dst to the product in*base where dst and base are the x
// coordinates of group points and all values are in little-endian form.
//
// Deprecated: when provided a low-order point, ScalarMult will set dst to all
// zeroes, irrespective of the scalar. Instead, use the X25519 function, which
// will return an error.
func ScalarMult(dst, in, base *[32]byte) {
	// If the `x/crypto/curve25519` package would be faster, and we
	// are not exercising the implementation provided by this package
	// (eg: testing or benchmarking), use that instead.
	if xcurveFaster && !debugNoXcurve {
		xcurve.ScalarMult(dst, in, base)
		return
	}

	var ec [32]byte
	copy(ec[:], in[:])
	clampScalar(&ec)

	var s scalar.Scalar
	if err := s.FromBits(ec[:]); err != nil {
		panic("primitives/x25519: failed to deserialize scalar: " + err.Error())
	}

	var montP curve.MontgomeryPoint
	if err := montP.FromBytes(base[:]); err != nil {
		panic("primitives/x25519: failed to deserialize point: " + err.Error())
	}

	montP.Mul(&montP, &s)
	copy(dst[:], montP[:])
}

// ScalarBaseMult sets dst to the product in*base where dst and base are
// the x coordinates of group points, base is the standard generator and
// all values are in little-endian form.
//
// It is recommended to use the X25519 function with Basepoint instead, as
// copying into fixed size arrays can lead to unexpected bugs.
func ScalarBaseMult(dst, in *[32]byte) {
	// There is no codepath to use `x/crypto/curve25519`'s version
	// as none of the targets use a precomputed implementation.

	var ec [32]byte
	copy(ec[:], in[:])
	clampScalar(&ec)

	var s scalar.Scalar
	if err := s.FromBits(ec[:]); err != nil {
		panic("primitives/x25519: failed to deserialize scalar: " + err.Error())
	}

	edP := curve.ED25519_BASEPOINT_TABLE.Mul(&s)

	var montP curve.MontgomeryPoint
	montP.FromEdwards(&edP)

	copy(dst[:], montP[:])
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are
// slices of 32 bytes.
//
// scalar can be generated at random, for example with crypto/rand. point should
// be either Basepoint or the output of another X25519 call.
//
// If point is Basepoint (but not if it's a different slice with the same
// contents) a precomputed implementation might be used for performance.
func X25519(scalar, point []byte) ([]byte, error) {
	// Outline the body of function, to let the allocation be inlined in the
	// caller, and possibly avoid escaping to the heap.
	var dst [32]byte
	return x25519(&dst, scalar, point)
}

func x25519(dst *[32]byte, scalar, point []byte) ([]byte, error) {
	var in [32]byte
	if l := len(scalar); l != 32 {
		return nil, fmt.Errorf("bad scalar length: %d, expected %d", l, 32)
	}
	if l := len(point); l != 32 {
		return nil, fmt.Errorf("bad point length: %d, expected %d", l, 32)
	}
	copy(in[:], scalar)
	if &point[0] == &Basepoint[0] {
		checkBasepoint()
		ScalarBaseMult(dst, &in)
	} else {
		var base, zero [32]byte
		copy(base[:], point)
		ScalarMult(dst, &in, &base)
		if subtle.ConstantTimeCompare(dst[:], zero[:]) == 1 {
			return nil, fmt.Errorf("bad input point: low order point")
		}
	}
	return dst[:], nil
}

func clampScalar(s *[scalar.ScalarSize]byte) {
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
}

func checkBasepoint() {
	if subtle.ConstantTimeCompare(Basepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) != 1 {
		panic("primitives/x25519: global Basepoint value was modified")
	}
}

func init() {
	Basepoint = basePoint[:]

	// Decide if `x/crypto/curve25519` is faster for the given
	// target or not.  For now this is decided entirely by the
	// presence of an optimized assembly implementation.
	//
	// TODO/perf:
	//  * If `purego` is defined, or `gc` is not defined then
	//    the assembly implementations will not be used.
	//  * At least for the generic scalar multiply, voi is likely
	//    to be slower on 32 bit targets.
	switch runtime.GOARCH {
	case "amd64":
		xcurveFaster = true
	default:
	}
}
