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

// +build amd64,!purego,!forcenoasm,!force32bit

#include "textflag.h"

DATA ·cached_id_0<>+0x00(SB)/4, $121647
DATA ·cached_id_0<>+0x04(SB)/4, $121666
DATA ·cached_id_0<>+0x08(SB)/4, $0
DATA ·cached_id_0<>+0x0c(SB)/4, $0
DATA ·cached_id_0<>+0x10(SB)/4, $243332
DATA ·cached_id_0<>+0x14(SB)/4, $67108845
DATA ·cached_id_0<>+0x18(SB)/4, $0
DATA ·cached_id_0<>+0x1c(SB)/4, $33554431
GLOBL ·cached_id_0<>(SB), (NOPTR+RODATA), $32

DATA ·cached_id_1<>+0x00(SB)/4, $67108864
DATA ·cached_id_1<>+0x04(SB)/4, $0
DATA ·cached_id_1<>+0x08(SB)/4, $33554431
DATA ·cached_id_1<>+0x0c(SB)/4, $0
DATA ·cached_id_1<>+0x10(SB)/4, $0
DATA ·cached_id_1<>+0x14(SB)/4, $67108863
DATA ·cached_id_1<>+0x18(SB)/4, $0
DATA ·cached_id_1<>+0x1c(SB)/4, $33554431
GLOBL ·cached_id_1<>(SB), (NOPTR+RODATA), $32

DATA ·cached_id_2_4<>+0x00(SB)/4, $67108863
DATA ·cached_id_2_4<>+0x04(SB)/4, $0
DATA ·cached_id_2_4<>+0x08(SB)/4, $33554431
DATA ·cached_id_2_4<>+0x0c(SB)/4, $0
DATA ·cached_id_2_4<>+0x10(SB)/4, $0
DATA ·cached_id_2_4<>+0x14(SB)/4, $67108863
DATA ·cached_id_2_4<>+0x18(SB)/4, $0
DATA ·cached_id_2_4<>+0x1c(SB)/4, $33554431
GLOBL ·cached_id_2_4<>(SB), (NOPTR+RODATA), $32

// func lookupAffineNiels_AVX2(table *affineNielsPointLookupTable, out *affineNielsPoint, xabs uint8)
TEXT ·lookupAffineNiels_AVX2(SB), NOSPLIT|NOFRAME, $0-17
	MOVQ table+0(FP), R14
	MOVQ out+8(FP), R15

	// This is moderately annoying due to having 5x3 64-bit elements, which
	// does not nicely fit into 256-bit registers.  This is handled by
	// duplicating one element in 2 ymm registers, since doing so keeps
	// the rest of the code straight forward.
	//
	// ymm0 = y_plus_x_0,  y_plus_x_1,  y_plus_x_2,  y_plus_x_3
	// ymm1 = y_plus_x_4,  y_minus_x_0, y_minus_x_1, y_minus_x_2
	// ymm2 = y_minus_x_3, y_minus_x_4, xy2d_0,      xy2d_1
	// ymm3 = xy2d_1 (*),  xy2d_2,      xy2d_3,      xy2d_4

	MOVBQZX      xabs+16(FP), AX
	VMOVD        AX, X14
	VPBROADCASTD X14, Y14
	VPXOR        Y0, Y0, Y0
	VPXOR        Y1, Y1, Y1
	VPXOR        Y2, Y2, Y2
	VPXOR        Y3, Y3, Y3

	// 0
	MOVD         $0, AX
	VMOVD        AX, X15
	VPBROADCASTD X15, Y15
	VPCMPEQD     Y14, Y15, Y15
	MOVQ         $1, AX
	VMOVQ        AX, X4
	VPINSRQ      $1, AX, X0, X5
	VPAND        Y15, Y4, Y4
	VPAND        Y15, Y5, Y5
	VPOR         Y0, Y4, Y0
	VPOR         Y1, Y5, Y1

	// 1 .. 8
	MOVQ $1, AX

affine_lookup_loop:
	VMOVD        AX, X15
	VPBROADCASTD X15, Y15
	VPCMPEQD     Y14, Y15, Y15
	VPAND        0(R14), Y15, Y4
	VPAND        32(R14), Y15, Y5
	VPAND        64(R14), Y15, Y6
	VPAND        88(R14), Y15, Y7
	VPOR         Y0, Y4, Y0
	VPOR         Y1, Y5, Y1
	VPOR         Y2, Y6, Y2
	VPOR         Y3, Y7, Y3
	ADDQ         $120, R14
	INCQ         AX
	CMPQ         AX, $8
	JLE          affine_lookup_loop

	VMOVDQU Y0, 0(R15)
	VMOVDQU Y1, 32(R15)
	VMOVDQU Y2, 64(R15)
	VMOVDQU Y3, 88(R15)

	VZEROUPPER
	RET

// func lookupCached(table, out *cachedPoint, xabs int8)
TEXT ·lookupCached(SB), NOSPLIT|NOFRAME, $0-17
	MOVQ table+0(FP), R14
	MOVQ out+8(FP), R15

	MOVBQZX      xabs+16(FP), AX
	VMOVD        AX, X14
	VPBROADCASTD X14, Y14
	VPXOR        Y0, Y0, Y0
	VPXOR        Y1, Y1, Y1
	VPXOR        Y2, Y2, Y2
	VPXOR        Y3, Y3, Y3
	VPXOR        Y4, Y4, Y4

	// 0
	MOVD         $0, AX
	VMOVD        AX, X15
	VPBROADCASTD X15, Y15
	VPCMPEQD     Y14, Y15, Y15
	VMOVDQA      ·cached_id_0<>(SB), Y5
	VMOVDQA      ·cached_id_1<>(SB), Y6
	VMOVDQA      ·cached_id_2_4<>(SB), Y7
	VMOVDQA      Y7, Y8
	VMOVDQA      Y7, Y9
	VPAND        Y15, Y5, Y5
	VPAND        Y15, Y6, Y6
	VPAND        Y15, Y7, Y7
	VPAND        Y15, Y8, Y8
	VPAND        Y15, Y9, Y9
	VPOR         Y0, Y5, Y0
	VPOR         Y1, Y6, Y1
	VPOR         Y2, Y7, Y2
	VPOR         Y3, Y8, Y3
	VPOR         Y4, Y9, Y4

	// 1 .. 8
	MOVQ $1, AX

cached_lookup_loop:
	VMOVD        AX, X15
	VPBROADCASTD X15, Y15
	VPCMPEQD     Y14, Y15, Y15
	VPAND        0(R14), Y15, Y5
	VPAND        32(R14), Y15, Y6
	VPAND        64(R14), Y15, Y7
	VPAND        96(R14), Y15, Y8
	VPAND        128(R14), Y15, Y9
	VPOR         Y0, Y5, Y0
	VPOR         Y1, Y6, Y1
	VPOR         Y2, Y7, Y2
	VPOR         Y3, Y8, Y3
	VPOR         Y4, Y9, Y4
	ADDQ         $160, R14
	INCQ         AX
	CMPQ         AX, $8
	JLE          cached_lookup_loop

	VMOVDQU Y0, 0(R15)
	VMOVDQU Y1, 32(R15)
	VMOVDQU Y2, 64(R15)
	VMOVDQU Y3, 96(R15)
	VMOVDQU Y4, 128(R15)

	VZEROUPPER
	RET
