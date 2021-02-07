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

// +build amd64,!purego,!forcenoasm

package field

import "golang.org/x/sys/cpu"

var useBMI2 bool

// In an ideal world, this would have the assembly language implementations
// split into separate routines based on which instructions are used, like
// this:
//
// func feMul(out, a, b *FieldElement) {
//     if useBMI2 {
//        feMul_BMI2(out, a, b)
//     } else {
//        feMul_AMD64(out, a, b)
//     }
// }
//
// However, the compiler will inline what we do now, and will NOT inline
// the cleaner version of the code.  The extra overhead of an extra
// function call obliterates the gains made by using BMI2 in the
// first place.
//
// Since we have control over our assembly language code, and do not have
// control over the inliner (because you know, that would be useful),
// things are done this way.

//go:noescape
func feMul_AMD64(out, a, b *FieldElement, useBMI2 bool)

//go:noescape
func fePow2k_AMD64(out *FieldElement, k uint, useBMI2 bool)

func feMul(out, a, b *FieldElement) {
	feMul_AMD64(out, a, b, useBMI2)
}

func fePow2k(out *FieldElement, k uint) {
	fePow2k_AMD64(out, k, useBMI2)
}

func init() {
	useBMI2 = cpu.Initialized && cpu.X86.HasBMI2
}
