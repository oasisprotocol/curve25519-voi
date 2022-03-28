// Copyright (c) 2021 Oasis Labs Inc. All rights reserved.
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

//nolint:deadcode,unused
package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/buildtags"
	. "github.com/mmcloughlin/avo/operand"
)

// Stub types to make the avo function signature parser behave without
// having to introduce avo as a dependency for the actual package.
type (
	affineNielsPointLookupTable struct{}
	affineNielsPoint            struct{}

	Element struct{}

	cachedPointLookupTable struct{}
	cachedPoint            struct{}
	extendedPoint          struct{}
	fieldElement2625x4     struct{}
)

// SetCommon sets the common file-level properties that are expected for all
// assembly files.
func SetCommon() error {
	// Use our stub types so we can declare nice function prototypes.
	Package(".")

	// We want `go:build amd64,!purego,!force32bit`
	c, err := buildtags.ParseConstraint("amd64,!purego,!force32bit")
	if err != nil {
		return fmt.Errorf("asm/amd64: failed to parse build constraint: %w", err)
	}
	Constraints(c)

	return nil
}

func newU32x8(name string, values [8]uint32) Mem {
	ref := GLOBL(name, RODATA|NOPTR)
	for i, v := range values {
		DATA(i*4, U32(v))
	}
	return ref
}

func newU64x4(name string, values [4]uint64) Mem {
	ref := GLOBL(name, RODATA|NOPTR)
	for i, v := range values {
		DATA(i*8, U64(v))
	}
	return ref
}

func MM_SHUFFLE(z, y, x, w uint8) Constant {
	return U8(z<<6 | y<<4 | x<<2 | w<<0)
}
