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

package curve

import "golang.org/x/sys/cpu"

var useAssembly bool

//go:noescape
func fastLookupProjectiveNiels_SSE2(table, out *projectiveNielsPoint, xabs uint64)

//go:noescape
func fastLookupAffineNiels_SSE2(table, out *byte, xabs uint64)

func (tbl *projectiveNielsPointLookupTable) fastLookup(out *projectiveNielsPoint, xabs int8) {
	fastLookupProjectiveNiels_SSE2(&tbl[0], out, uint64(xabs))
}

func (tbl *packedAffineNielsPointLookupTable) fastLookup(out *[96]byte, xabs int8) {
	fastLookupAffineNiels_SSE2(&tbl[0][0], &out[0], uint64(xabs))
}

func init() {
	useAssembly = cpu.Initialized && cpu.X86.HasSSE2
}
