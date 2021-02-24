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

// +build !purego

package subtle

import (
	"crypto/subtle"
	"runtime"
	"strconv"
	"unsafe"
)

var unalignedOk bool //nolint: unused

func MoveConditionalBytesx96(out, in *[96]byte, flag uint64) { //nolint:unused,deadcode
	inp := unsafe.Pointer(&in[0])
	outp := unsafe.Pointer(&out[0])

	// Pick the fastest possible path based on the alignment of out/in
	// and the CPU's register size.
	switch strconv.IntSize {
	case 64:
		// Require 64 bit alignment for the fast path.
		if unalignedOk || (uintptr(inp)&0x07 == 0 && uintptr(outp)&0x7 == 0) {
			moveConditionalBytes64(outp, inp, flag)
			return
		}
		fallthrough // We might still be able to use the 32 bit path.
	case 32:
		// Require 32 bit alignment for the fast path.
		if unalignedOk || (uintptr(inp)&0x3 == 0 && uintptr(outp)&0x3 == 0) {
			moveConditionalBytes32(outp, inp, flag)
			return
		}
	default:
	}

	subtle.ConstantTimeCopy(int(flag), out[:], in[:])
}

func moveConditionalBytes64(outp, inp unsafe.Pointer, flag uint64) { //nolint:unused
	inq, outq := (*[12]uint64)(inp), (*[12]uint64)(outp)

	var (
		nb = flag - 1
		b  = ^nb
	)
	outq[0] = (outq[0] & nb) | (inq[0] & b)
	outq[1] = (outq[1] & nb) | (inq[1] & b)
	outq[2] = (outq[2] & nb) | (inq[2] & b)
	outq[3] = (outq[3] & nb) | (inq[3] & b)
	outq[4] = (outq[4] & nb) | (inq[4] & b)
	outq[5] = (outq[5] & nb) | (inq[5] & b)
	outq[6] = (outq[6] & nb) | (inq[6] & b)
	outq[7] = (outq[7] & nb) | (inq[7] & b)
	outq[8] = (outq[8] & nb) | (inq[8] & b)
	outq[9] = (outq[9] & nb) | (inq[9] & b)
	outq[10] = (outq[10] & nb) | (inq[10] & b)
	outq[11] = (outq[11] & nb) | (inq[11] & b)
}

func moveConditionalBytes32(outp, inp unsafe.Pointer, flag uint64) { //nolint:unused
	inq, outq := (*[24]uint32)(inp), (*[24]uint32)(outp)

	var (
		nb = uint32(flag) - 1
		b  = ^nb
	)
	outq[0] = (outq[0] & nb) | (inq[0] & b)
	outq[1] = (outq[1] & nb) | (inq[1] & b)
	outq[2] = (outq[2] & nb) | (inq[2] & b)
	outq[3] = (outq[3] & nb) | (inq[3] & b)
	outq[4] = (outq[4] & nb) | (inq[4] & b)
	outq[5] = (outq[5] & nb) | (inq[5] & b)
	outq[6] = (outq[6] & nb) | (inq[6] & b)
	outq[7] = (outq[7] & nb) | (inq[7] & b)
	outq[8] = (outq[8] & nb) | (inq[8] & b)
	outq[9] = (outq[9] & nb) | (inq[9] & b)
	outq[10] = (outq[10] & nb) | (inq[10] & b)
	outq[11] = (outq[11] & nb) | (inq[11] & b)
	outq[12] = (outq[12] & nb) | (inq[12] & b)
	outq[13] = (outq[13] & nb) | (inq[13] & b)
	outq[14] = (outq[14] & nb) | (inq[14] & b)
	outq[15] = (outq[15] & nb) | (inq[15] & b)
	outq[16] = (outq[16] & nb) | (inq[16] & b)
	outq[17] = (outq[17] & nb) | (inq[17] & b)
	outq[18] = (outq[18] & nb) | (inq[18] & b)
	outq[19] = (outq[19] & nb) | (inq[19] & b)
	outq[20] = (outq[20] & nb) | (inq[20] & b)
	outq[21] = (outq[21] & nb) | (inq[21] & b)
	outq[22] = (outq[22] & nb) | (inq[22] & b)
	outq[23] = (outq[23] & nb) | (inq[23] & b)
}

func init() {
	switch runtime.GOARCH {
	case "amd64", "386", "ppc64le": // TODO: Any more architectures?
		unalignedOk = true
	default:
	}
}
