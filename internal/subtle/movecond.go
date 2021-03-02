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

package subtle

import (
	"encoding/binary"
	"strconv"
)

func MoveConditionalBytesx96(out, in *[96]byte, flag uint64) {
	// The standard library's `subtle.ConstantTimeCopy` method is an
	// obvious choice here, but it's performance is trash, and unlikely
	// to be improved.

	switch strconv.IntSize {
	case 64:
		var (
			nb = flag - 1
			b  = ^nb
		)
		in0 := binary.LittleEndian.Uint64(in[0:8])
		in1 := binary.LittleEndian.Uint64(in[8:16])
		in2 := binary.LittleEndian.Uint64(in[16:24])
		in3 := binary.LittleEndian.Uint64(in[24:32])
		in4 := binary.LittleEndian.Uint64(in[32:40])
		in5 := binary.LittleEndian.Uint64(in[40:48])
		in6 := binary.LittleEndian.Uint64(in[48:56])
		in7 := binary.LittleEndian.Uint64(in[56:64])
		in8 := binary.LittleEndian.Uint64(in[64:72])
		in9 := binary.LittleEndian.Uint64(in[72:80])
		in10 := binary.LittleEndian.Uint64(in[80:88])
		in11 := binary.LittleEndian.Uint64(in[88:96])

		out0 := binary.LittleEndian.Uint64(out[0:8])
		out1 := binary.LittleEndian.Uint64(out[8:16])
		out2 := binary.LittleEndian.Uint64(out[16:24])
		out3 := binary.LittleEndian.Uint64(out[24:32])
		out4 := binary.LittleEndian.Uint64(out[32:40])
		out5 := binary.LittleEndian.Uint64(out[40:48])
		out6 := binary.LittleEndian.Uint64(out[48:56])
		out7 := binary.LittleEndian.Uint64(out[56:64])
		out8 := binary.LittleEndian.Uint64(out[64:72])
		out9 := binary.LittleEndian.Uint64(out[72:80])
		out10 := binary.LittleEndian.Uint64(out[80:88])
		out11 := binary.LittleEndian.Uint64(out[88:96])

		binary.LittleEndian.PutUint64(out[0:8], (out0&nb)|(in0&b))
		binary.LittleEndian.PutUint64(out[8:16], (out1&nb)|(in1&b))
		binary.LittleEndian.PutUint64(out[16:24], (out2&nb)|(in2&b))
		binary.LittleEndian.PutUint64(out[24:32], (out3&nb)|(in3&b))
		binary.LittleEndian.PutUint64(out[32:40], (out4&nb)|(in4&b))
		binary.LittleEndian.PutUint64(out[40:48], (out5&nb)|(in5&b))
		binary.LittleEndian.PutUint64(out[48:56], (out6&nb)|(in6&b))
		binary.LittleEndian.PutUint64(out[56:64], (out7&nb)|(in7&b))
		binary.LittleEndian.PutUint64(out[64:72], (out8&nb)|(in8&b))
		binary.LittleEndian.PutUint64(out[72:80], (out9&nb)|(in9&b))
		binary.LittleEndian.PutUint64(out[80:88], (out10&nb)|(in10&b))
		binary.LittleEndian.PutUint64(out[88:96], (out11&nb)|(in11&b))
	default:
		// This could be unrolled, but the user is already running on
		// something that I could power with a potato battery, so why
		// bother.
		var (
			nb = uint32(flag) - 1
			b  = ^nb
		)

		for i := 0; i < 96; i += 4 {
			inq := binary.LittleEndian.Uint32(in[i : i+4])
			outq := binary.LittleEndian.Uint32(out[i : i+4])
			binary.LittleEndian.PutUint32(out[i:i+4], (outq&nb)|(inq&b))
		}
	}
}
