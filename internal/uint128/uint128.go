// Copyright (c) 2019 Oasis Labs Inc.  All rights reserved.
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
//    * Neither the name of Oasis Labs Inc. nor the names of its
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

// Package uint128 provides a basic unsigned 128 bit integer implementation.
package uint128

import "math/bits"

// Uint128 is an unsigned 128 bit integer represented as 2 uint64 limbs.
type Uint128 struct {
	hi uint64
	lo uint64
}

// SetUint64 sets `out` to the to the u64.
func SetUint64(out *Uint128, v uint64) {
	out.hi = 0
	out.lo = v
}

// Mul sets `out` to the full 128 bit result of `a * b`.
func Mul64x64(out *Uint128, a, b uint64) {
	out.hi, out.lo = bits.Mul64(a, b)
}

// Shr sets `a` to the full 128 bit result of `a >> shift`.
//
// WARNING: shift must be <= 64.
func Shr(a *Uint128, shift uint8) {
	hi, lo := a.hi, a.lo
	lo = (hi << (64 - shift)) | (lo >> shift)
	hi = hi >> shift
	a.hi, a.lo = hi, lo
}

// ShrLo returns the low 64 bits of `a >> shift`.
func ShrLo(a *Uint128, shift uint64) uint64 {
	return (a.hi << (64 - shift)) | (a.lo >> shift)
}

// Add sets `a` to the full 128 bit result of `a + b`.
func Add(a, b *Uint128) {
	var carry uint64
	a.lo, carry = bits.Add64(a.lo, b.lo, 0)
	a.hi, _ = bits.Add64(a.hi, b.hi, carry)
}

// Add64 sets `a` to the full 128 bit result of `a + b`.
func Add64(a *Uint128, b uint64) {
	var carry uint64
	a.lo, carry = bits.Add64(a.lo, b, 0)
	a.hi, _ = bits.Add64(a.hi, 0, carry)
}

// Lo returns the low 64 bits of `a`.
func Lo(a *Uint128) uint64 {
	return a.lo
}

// Hi returns the high 64 bits of `a`.
func Hi(a *Uint128) uint64 {
	return a.hi
}

// Mul64x64Add sets `inOut` to the full 128 bit result of `inOut + (a * b)`.
func Mul64x64Add(inOut *Uint128, a, b uint64) {
	var product Uint128
	Mul64x64(&product, a, b)
	Add(inOut, &product)
}
