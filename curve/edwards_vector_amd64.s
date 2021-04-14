// Copyright (c) 2016-2019 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
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

// +build amd64,!purego,!forcenoasm,!force32bit

#include "textflag.h"

DATA ·p_times_2_lo<>+0x00(SB)/4, $134217690 // 67108845 << 1
DATA ·p_times_2_lo<>+0x04(SB)/4, $134217690
DATA ·p_times_2_lo<>+0x08(SB)/4, $67108862 // 33554431 << 1
DATA ·p_times_2_lo<>+0x0c(SB)/4, $67108862
DATA ·p_times_2_lo<>+0x10(SB)/4, $134217690
DATA ·p_times_2_lo<>+0x14(SB)/4, $134217690
DATA ·p_times_2_lo<>+0x18(SB)/4, $67108862
DATA ·p_times_2_lo<>+0x1c(SB)/4, $67108862
GLOBL ·p_times_2_lo<>(SB), (NOPTR+RODATA), $32

DATA ·p_times_2_hi<>+0x00(SB)/4, $134217726 // 67108863 << 1
DATA ·p_times_2_hi<>+0x04(SB)/4, $134217726
DATA ·p_times_2_hi<>+0x08(SB)/4, $67108862 // 33554431 << 1
DATA ·p_times_2_hi<>+0x0c(SB)/4, $67108862
DATA ·p_times_2_hi<>+0x10(SB)/4, $134217726
DATA ·p_times_2_hi<>+0x14(SB)/4, $134217726
DATA ·p_times_2_hi<>+0x18(SB)/4, $67108862
DATA ·p_times_2_hi<>+0x1c(SB)/4, $67108862
GLOBL ·p_times_2_hi<>(SB), (NOPTR+RODATA), $32

DATA ·p_times_16_lo<>+0x00(SB)/4, $1073741520 // 67108845 << 4
DATA ·p_times_16_lo<>+0x04(SB)/4, $1073741520
DATA ·p_times_16_lo<>+0x08(SB)/4, $536870896 // 33554431 << 4
DATA ·p_times_16_lo<>+0x0c(SB)/4, $536870896
DATA ·p_times_16_lo<>+0x10(SB)/4, $1073741520
DATA ·p_times_16_lo<>+0x14(SB)/4, $1073741520
DATA ·p_times_16_lo<>+0x18(SB)/4, $536870896
DATA ·p_times_16_lo<>+0x1c(SB)/4, $536870896
GLOBL ·p_times_16_lo<>(SB), (NOPTR+RODATA), $32

DATA ·p_times_16_hi<>+0x00(SB)/4, $1073741808 // 67108863 << 4
DATA ·p_times_16_hi<>+0x04(SB)/4, $1073741808
DATA ·p_times_16_hi<>+0x08(SB)/4, $536870896 // 33554431 << 4
DATA ·p_times_16_hi<>+0x0c(SB)/4, $536870896
DATA ·p_times_16_hi<>+0x10(SB)/4, $1073741808
DATA ·p_times_16_hi<>+0x14(SB)/4, $1073741808
DATA ·p_times_16_hi<>+0x18(SB)/4, $536870896
DATA ·p_times_16_hi<>+0x1c(SB)/4, $536870896
GLOBL ·p_times_16_hi<>(SB), (NOPTR+RODATA), $32

DATA ·reduce_shifts<>+0x00(SB)/4, $26
DATA ·reduce_shifts<>+0x04(SB)/4, $26
DATA ·reduce_shifts<>+0x08(SB)/4, $25
DATA ·reduce_shifts<>+0x0c(SB)/4, $25
DATA ·reduce_shifts<>+0x10(SB)/4, $26
DATA ·reduce_shifts<>+0x14(SB)/4, $26
DATA ·reduce_shifts<>+0x18(SB)/4, $25
DATA ·reduce_shifts<>+0x1c(SB)/4, $25
GLOBL ·reduce_shifts<>(SB), (NOPTR+RODATA), $32

DATA ·reduce_masks<>+0x00(SB)/4, $0x3ffffff // (1 << 26) - 1
DATA ·reduce_masks<>+0x04(SB)/4, $0x3ffffff
DATA ·reduce_masks<>+0x08(SB)/4, $0x1ffffff // (1 << 25) - 1
DATA ·reduce_masks<>+0x0c(SB)/4, $0x1ffffff
DATA ·reduce_masks<>+0x10(SB)/4, $0x3ffffff
DATA ·reduce_masks<>+0x14(SB)/4, $0x3ffffff
DATA ·reduce_masks<>+0x18(SB)/4, $0x1ffffff
DATA ·reduce_masks<>+0x1c(SB)/4, $0x1ffffff
GLOBL ·reduce_masks<>(SB), (NOPTR+RODATA), $32

DATA ·v19<>+0x00(SB)/8, $19
DATA ·v19<>+0x08(SB)/8, $19
DATA ·v19<>+0x10(SB)/8, $19
DATA ·v19<>+0x18(SB)/8, $19
GLOBL ·v19<>(SB), (NOPTR+RODATA), $32

DATA ·low_25_bit_mask<>+0x00(SB)/8, $0x1ffffff
DATA ·low_25_bit_mask<>+0x08(SB)/8, $0x1ffffff
DATA ·low_25_bit_mask<>+0x10(SB)/8, $0x1ffffff
DATA ·low_25_bit_mask<>+0x18(SB)/8, $0x1ffffff
GLOBL ·low_25_bit_mask<>(SB), (NOPTR+RODATA), $32

DATA ·low_26_bit_mask<>+0x00(SB)/8, $0x3ffffff
DATA ·low_26_bit_mask<>+0x08(SB)/8, $0x3ffffff
DATA ·low_26_bit_mask<>+0x10(SB)/8, $0x3ffffff
DATA ·low_26_bit_mask<>+0x18(SB)/8, $0x3ffffff
GLOBL ·low_26_bit_mask<>(SB), (NOPTR+RODATA), $32

DATA ·low_p_37<>+0x00(SB)/8, $0x7ffffda000000000 // 0x3ffffed << 37
DATA ·low_p_37<>+0x08(SB)/8, $0x7ffffda000000000
DATA ·low_p_37<>+0x10(SB)/8, $0x7ffffda000000000
DATA ·low_p_37<>+0x18(SB)/8, $0x7ffffda000000000
GLOBL ·low_p_37<>(SB), (NOPTR+RODATA), $32

DATA ·even_p_37<>+0x00(SB)/8, $0x7fffffe000000000 // 0x3ffffff << 37
DATA ·even_p_37<>+0x08(SB)/8, $0x7fffffe000000000
DATA ·even_p_37<>+0x10(SB)/8, $0x7fffffe000000000
DATA ·even_p_37<>+0x18(SB)/8, $0x7fffffe000000000
GLOBL ·even_p_37<>(SB), (NOPTR+RODATA), $32

DATA ·odd_p_37<>+0x00(SB)/8, $0x3fffffe000000000 // 0x1ffffff << 37
DATA ·odd_p_37<>+0x08(SB)/8, $0x3fffffe000000000
DATA ·odd_p_37<>+0x10(SB)/8, $0x3fffffe000000000
DATA ·odd_p_37<>+0x18(SB)/8, $0x3fffffe000000000
GLOBL ·odd_p_37<>(SB), (NOPTR+RODATA), $32

DATA ·shuffle_AAAA<>+0x00(SB)/4, $0
DATA ·shuffle_AAAA<>+0x04(SB)/4, $0
DATA ·shuffle_AAAA<>+0x08(SB)/4, $2
DATA ·shuffle_AAAA<>+0x0c(SB)/4, $2
DATA ·shuffle_AAAA<>+0x10(SB)/4, $0
DATA ·shuffle_AAAA<>+0x14(SB)/4, $0
DATA ·shuffle_AAAA<>+0x18(SB)/4, $2
DATA ·shuffle_AAAA<>+0x1c(SB)/4, $2
GLOBL ·shuffle_AAAA<>(SB), (NOPTR+RODATA), $32 // (VPERMD 0, 0, 2, 2, 0, 0, 2, 2)

DATA ·shuffle_BBBB<>+0x00(SB)/4, $1
DATA ·shuffle_BBBB<>+0x04(SB)/4, $1
DATA ·shuffle_BBBB<>+0x08(SB)/4, $3
DATA ·shuffle_BBBB<>+0x0c(SB)/4, $3
DATA ·shuffle_BBBB<>+0x10(SB)/4, $1
DATA ·shuffle_BBBB<>+0x14(SB)/4, $1
DATA ·shuffle_BBBB<>+0x18(SB)/4, $3
DATA ·shuffle_BBBB<>+0x1c(SB)/4, $3
GLOBL ·shuffle_BBBB<>(SB), (NOPTR+RODATA), $32 // (VPERMD 1, 1, 3, 3, 1, 1, 3, 3)

DATA ·shuffle_CACA<>+0x00(SB)/4, $4
DATA ·shuffle_CACA<>+0x04(SB)/4, $0
DATA ·shuffle_CACA<>+0x08(SB)/4, $6
DATA ·shuffle_CACA<>+0x0c(SB)/4, $2
DATA ·shuffle_CACA<>+0x10(SB)/4, $4
DATA ·shuffle_CACA<>+0x14(SB)/4, $0
DATA ·shuffle_CACA<>+0x18(SB)/4, $6
DATA ·shuffle_CACA<>+0x1c(SB)/4, $2
GLOBL ·shuffle_CACA<>(SB), (NOPTR+RODATA), $32 // (VPERMD 4, 0, 6, 2, 4, 0, 6, 2)

DATA ·shuffle_DBBD<>+0x00(SB)/4, $5
DATA ·shuffle_DBBD<>+0x04(SB)/4, $1
DATA ·shuffle_DBBD<>+0x08(SB)/4, $7
DATA ·shuffle_DBBD<>+0x0c(SB)/4, $3
DATA ·shuffle_DBBD<>+0x10(SB)/4, $1
DATA ·shuffle_DBBD<>+0x14(SB)/4, $5
DATA ·shuffle_DBBD<>+0x18(SB)/4, $3
DATA ·shuffle_DBBD<>+0x1c(SB)/4, $7
GLOBL ·shuffle_DBBD<>(SB), (NOPTR+RODATA), $32 // (VPERMD 5, 1, 7, 3, 1, 5, 3, 7)

DATA ·shuffle_ADDA<>+0x00(SB)/4, $0
DATA ·shuffle_ADDA<>+0x04(SB)/4, $5
DATA ·shuffle_ADDA<>+0x08(SB)/4, $2
DATA ·shuffle_ADDA<>+0x0c(SB)/4, $7
DATA ·shuffle_ADDA<>+0x10(SB)/4, $5
DATA ·shuffle_ADDA<>+0x14(SB)/4, $0
DATA ·shuffle_ADDA<>+0x18(SB)/4, $7
DATA ·shuffle_ADDA<>+0x1c(SB)/4, $2
GLOBL ·shuffle_ADDA<>(SB), (NOPTR+RODATA), $32 // (VPERMD  0, 5, 2, 7, 5, 0, 7, 2)

DATA ·shuffle_CBCB<>+0x00(SB)/4, $4
DATA ·shuffle_CBCB<>+0x04(SB)/4, $1
DATA ·shuffle_CBCB<>+0x08(SB)/4, $6
DATA ·shuffle_CBCB<>+0x0c(SB)/4, $3
DATA ·shuffle_CBCB<>+0x10(SB)/4, $4
DATA ·shuffle_CBCB<>+0x14(SB)/4, $1
DATA ·shuffle_CBCB<>+0x18(SB)/4, $6
DATA ·shuffle_CBCB<>+0x1c(SB)/4, $3
GLOBL ·shuffle_CBCB<>(SB), (NOPTR+RODATA), $32 // (VPERMD 4, 1, 6, 3, 4, 1, 6, 3)

#define SHUFFLE_ABAB $0x44 // 0b01_00_01_00 (VPERMQ 1, 0, 1, 0)
#define SHUFFLE_BADC $0xb1 // 0b10_11_00_01 (VPSHUFD 2, 3, 0, 1)

DATA ·shuffle_BACD<>+0x00(SB)/4, $1
DATA ·shuffle_BACD<>+0x04(SB)/4, $0
DATA ·shuffle_BACD<>+0x08(SB)/4, $3
DATA ·shuffle_BACD<>+0x0c(SB)/4, $2
DATA ·shuffle_BACD<>+0x10(SB)/4, $4
DATA ·shuffle_BACD<>+0x14(SB)/4, $5
DATA ·shuffle_BACD<>+0x18(SB)/4, $6
DATA ·shuffle_BACD<>+0x1c(SB)/4, $7
GLOBL ·shuffle_BACD<>(SB), (NOPTR+RODATA), $32 // (VPERMD 1, 0, 3, 2, 4, 5, 6, 7)

DATA ·shuffle_ABDC<>+0x00(SB)/4, $0
DATA ·shuffle_ABDC<>+0x04(SB)/4, $1
DATA ·shuffle_ABDC<>+0x08(SB)/4, $2
DATA ·shuffle_ABDC<>+0x0c(SB)/4, $3
DATA ·shuffle_ABDC<>+0x10(SB)/4, $5
DATA ·shuffle_ABDC<>+0x14(SB)/4, $4
DATA ·shuffle_ABDC<>+0x18(SB)/4, $7
DATA ·shuffle_ABDC<>+0x1c(SB)/4, $6
GLOBL ·shuffle_ABDC<>(SB), (NOPTR+RODATA), $32 // (VPERMD 0, 1, 2, 3, 5, 4, 7, 6)

DATA ·to_cached_scalar<>+0x00(SB)/4, $0x1db42 // 121666
DATA ·to_cached_scalar<>+0x04(SB)/4, $0x0
DATA ·to_cached_scalar<>+0x08(SB)/4, $0x1db42
DATA ·to_cached_scalar<>+0x0c(SB)/4, $0x0
DATA ·to_cached_scalar<>+0x10(SB)/4, $0x3b684 // 2 * 121666
DATA ·to_cached_scalar<>+0x14(SB)/4, $0x0
DATA ·to_cached_scalar<>+0x18(SB)/4, $0x3b682 // 2 * 121665
DATA ·to_cached_scalar<>+0x1c(SB)/4, $0x0
GLOBL ·to_cached_scalar<>(SB), (NOPTR+RODATA), $32

#define LANES_C $0x50 // 0101_0000
#define LANES_D $0xa0 // 1010_0000

#define LANES_AB $0x0f // 0000_0101 | 0000_1010
#define LANES_AC $0x55 // 0000_0101 | 0101_0000
#define LANES_AD $0xa5 // 0000_0101 | 1010_0000
#define LANES_BC $0x5a // 0000_1010 | 0101_0000

#define LANES_D64 $0xc0 // 11_00_00_00

// load_vec loads the vector of field elements starting from base into
// ymm0 .. ymm4.
#define load_vec(base) \
	VMOVDQU 0(base), Y0   \
	VMOVDQU 32(base), Y1  \
	VMOVDQU 64(base), Y2  \
	VMOVDQU 96(base), Y3  \
	VMOVDQU 128(base), Y4 \

// store_vec stores the vector of field elements in ymm0 .. ymm4 into
// memory starting from base.
#define store_vec(base) \
	VMOVDQU Y0, 0(base)   \
	VMOVDQU Y1, 32(base)  \
	VMOVDQU Y2, 64(base)  \
	VMOVDQU Y3, 96(base)  \
	VMOVDQU Y4, 128(base) \

// store_vec_2 stores the vector of field elements in ymm5 .. ymm9 into
// memory startig from base.
#define store_vec_2(base) \
	VMOVDQU Y5, 0(base)   \
	VMOVDQU Y6, 32(base)  \
	VMOVDQU Y7, 64(base)  \
	VMOVDQU Y8, 96(base)  \
	VMOVDQU Y9, 128(base) \

// func vecConditionalSelect_AVX2(out, a, b *fieldElement2625x4, mask uint32)
TEXT ·vecConditionalSelect_AVX2(SB), NOSPLIT|NOFRAME, $0-28
	MOVQ out+0(FP), CX
	MOVQ a+8(FP), AX
	MOVQ b+16(FP), BX

	// ymm15 = [mask, .., mask]
	VPBROADCASTD mask+24(FP), Y15

	// ymm0 .. ymm4 = a
	load_vec(AX)

	// ymm5 .. ymm9 = a ^ b
	VPXOR 0(BX), Y0, Y5
	VPXOR 32(BX), Y1, Y6
	VPXOR 64(BX), Y2, Y7
	VPXOR 96(BX), Y3, Y8
	VPXOR 128(BX), Y4, Y9

	// ymm5 .. ymm9 &= mask
	VPAND Y15, Y5, Y5
	VPAND Y15, Y6, Y6
	VPAND Y15, Y7, Y7
	VPAND Y15, Y8, Y8
	VPAND Y15, Y9, Y9

	// ymm0 .. ymm4 = a ^ ((a ^ b) & mask)
	VPXOR Y0, Y5, Y0
	VPXOR Y1, Y6, Y1
	VPXOR Y2, Y7, Y2
	VPXOR Y3, Y8, Y3
	VPXOR Y4, Y9, Y4

	// out = ymm0 .. ymm4
	store_vec(CX)

	VZEROUPPER
	RET

// reduce reduces the field elements stored in ymm0, .. ymm4, and writes
// the result to memory starting at rax.
//
// Inputs:   ymm0 .. ymm4, rax
// Clobbers: ymm0 .. ymm14
#define reduce() \
	VMOVDQA  ·reduce_shifts<>(SB), Y15    \ // ymm15 <- reduce_shifts
	VMOVDQA  ·reduce_masks<>(SB), Y14     \ // ymm14 <- reduce_masks
	VPXOR    Y12, Y12, Y12                \ // ymm12 = 0
	                                      \
	\ // ymm5 .. ymm9 =  c10 ... c98
	VPSRLVD  Y15, Y0, Y5                  \
	VPSRLVD  Y15, Y1, Y6                  \
	VPSRLVD  Y15, Y2, Y7                  \
	VPSRLVD  Y15, Y3, Y8                  \
	VPSRLVD  Y15, Y4, Y9                  \
	VPSHUFD  $0x4e, Y5, Y5                \ // ymm5 = c10
	VPSHUFD  $0x4e, Y6, Y6                \ // ymm6 = c32
	VPSHUFD  $0x4e, Y7, Y7                \ // ymm7 = c54
	VPSHUFD  $0x4e, Y8, Y8                \ // ymm8 = c76
	VPSHUFD  $0x4e, Y9, Y9                \ // ymm9 = c98
	                                      \
	\ // ymm0 .. ymm4 &= masks
	VPAND    Y14, Y0, Y0                  \
	VPAND    Y14, Y1, Y1                  \
	VPAND    Y14, Y2, Y2                  \
	VPAND    Y14, Y3, Y3                  \
	VPAND    Y14, Y4, Y4                  \
	                                      \
	\ // ymm10 .. ymm14 = combine(lo, hi)
	VPBLENDD $0xcc, Y5, Y12, Y10          \ // combine(0, c10)
	VPBLENDD $0xcc, Y6, Y5, Y11           \ // combine(c10, c32)
	VPBLENDD $0xcc, Y7, Y6, Y12           \ // combine(c32, c54)
	VPBLENDD $0xcc, Y8, Y7, Y13           \ // combine(c54, c76)
	VPBLENDD $0xcc, Y9, Y8, Y14           \ // combine(c76, c98)
	                                      \
	\ // ymm0 .. ymm4 += ymm10 .. ymm14
	VPADDD   Y0, Y10, Y0                  \
	VPADDD   Y1, Y11, Y1                  \
	VPADDD   Y2, Y12, Y2                  \
	VPADDD   Y3, Y13, Y3                  \
	VPADDD   Y4, Y14, Y4                  \
	                                      \
	\ // ymm9 = c9_19
	VPSHUFD  $0xd8, Y9, Y9                \ // ymm9 = c9_spread
	VPMULUDQ ·v19<>(SB), Y9, Y9           \ // ymm9 = c9_19_spread
	VPSHUFD  $0xd8, Y9, Y9                \ // ymm9 = c9_19
	                                      \
	\ // ymm0 += c9_19
	VPADDD   Y0, Y9, Y0                   \
	                                      \
	\ // out = ymm0 .. ymm4
	store_vec(AX)                         \

// func vecReduce_AVX2(out *fieldElement2625x4)
TEXT ·vecReduce_AVX2(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ out+0(FP), AX

	// ymm0 .. ymm4 = out
	load_vec(AX)

	reduce()

	VZEROUPPER
	RET

// func vecNegate_AVX2(out *FieldElement2625x4)
TEXT ·vecNegate_AVX2(SB), NOSPLIT|NOFRAME, $0-8
	MOVQ out+0(FP), AX

	VMOVDQA ·p_times_16_lo<>(SB), Y15 // ymm15 <- P_TIMES_16_LO
	VMOVDQA ·p_times_16_hi<>(SB), Y14 // ymm14 <- P_TIMES_16_HI

	VPSUBD 0(AX), Y15, Y0   // ymm0 = P_TIMES_16_LO - out0
	VPSUBD 32(AX), Y14, Y1  // ymm1 = P_TIMES_16_HI - out1
	VPSUBD 64(AX), Y14, Y2  // ymm2 = P_TIMES_16_HI - out2
	VPSUBD 96(AX), Y14, Y3  // ymm3 = P_TIMES_16_HI - out3
	VPSUBD 128(AX), Y14, Y4 // ymm4 = P_TIMES_16_HI - out4

	reduce()

	VZEROUPPER
	RET

// repack_pair re-packs 2 64-bit lanes into a single 32-bit lane.
#define repack_pair(x, y) \
	VPSHUFD  $0xd8, x, x    \ // 0b11_01_10_00
	VPSHUFD  $0x8d, y, y    \ // 0b10_00_11_01
	VPBLENDD $0xcc, y, x, x \

// reduce64 reduces the intermediaries stored in ymm0, .. ymm9, and
// writes the result to memory starting at rax.
//
// Inputs:   ymm0 .. ymm9, rax
// Clobbers: ymm0 .. ymm14
#define reduce64() \
	VMOVDQA  ·low_25_bit_mask<>(SB), Y12 \ // ymm12 <- low_25_bit_mask
	VMOVDQA  ·low_26_bit_mask<>(SB), Y13 \ // ymm13 <- low_26_bit_mask
	VMOVDQA  ·v19<>(SB), Y14             \ // ymm14 <- v19
	                                     \
	VPSRLQ   $26, Y0, Y10                \ // ymm10 = ymm0 >> 26
	VPSRLQ   $26, Y4, Y11                \ // ymm11 = ymm4 >> 26
	VPADDQ   Y1, Y10, Y1                 \ // ymm1  = ymm1 + (ymm0 >> 26)
	VPADDQ   Y5, Y11, Y5                 \ // ymm5  = ymm5 + (ymm4 >> 26)
	VPAND    Y13, Y0, Y0                 \ // ymm0  = ymm0 & low_26_bit_mask
	VPAND    Y13, Y4, Y4                 \ // ymm4  = ymm4 & low_26_bit_mask
	                                     \
	VPSRLQ   $25, Y1, Y10                \ // ymm10 = ymm1 >> 25
	VPSRLQ   $25, Y5, Y11                \ // ymm11 = ymm5 >> 25
	VPADDQ   Y2, Y10, Y2                 \ // ymm2  = ymm2 + (ymm1 >> 25)
	VPADDQ   Y6, Y11, Y6                 \ // ymm6  = ymm6 + (ymm5 >> 25)
	VPAND    Y12, Y1, Y1                 \ // ymm1  = ymm1 & low_25_bit_mask
	VPAND    Y12, Y5, Y5                 \ // ymm5  = ymm5 & low_25_bit_mask
	                                     \
	VPSRLQ   $26, Y2, Y10                \ // ymm10 = ymm2 >> 26
	VPSRLQ   $26, Y6, Y11                \ // ymm11 = ymm6 >> 26
	VPADDQ   Y3, Y10, Y3                 \ // ymm3  = ymm3 + (ymm2 >> 26)
	VPADDQ   Y7, Y11, Y7                 \ // ymm7  = ymm7 + (ymm6 >> 26)
	VPAND    Y13, Y2, Y2                 \ // ymm2  = ymm2 & low_26_bit_mask
	VPAND    Y13, Y6, Y6                 \ // ymm6  = ymm6 & low_26_bit_mask
	                                     \
	VPSRLQ   $25, Y3, Y10                \ // ymm10 = ymm3 >> 25
	VPSRLQ   $25, Y7, Y11                \ // ymm11 = ymm7 >> 25
	VPADDQ   Y4, Y10, Y4                 \ // ymm4  = ymm4 + (ymm3 >> 25)
	VPADDQ   Y8, Y11, Y8                 \ // ymm8  = ymm8 + (ymm7 >> 25)
	VPAND    Y12, Y3, Y3                 \ // ymm3  = ymm3 & low_25_bit_mask
	VPAND    Y12, Y7, Y7                 \ // ymm7  = ymm7 & low_25_bit_mask
	                                     \
	VPSRLQ   $26, Y4, Y10                \ // ymm10 = ymm4 >> 26
	VPSRLQ   $26, Y8, Y11                \ // ymm11 = ymm8 >> 26
	VPADDQ   Y5, Y10, Y5                 \ // ymm5  = ymm5 + (ymm4 >> 26)
	VPADDQ   Y9, Y11, Y9                 \ // ymm9  = ymm9 + (ymm8 >> 26)
	VPAND    Y13, Y4, Y4                 \ // ymm4  = ymm4 & low_26_bit_mask
	VPAND    Y13, Y8, Y8                 \ // ymm8  = ymm8 & low_26_bit_mask
	                                     \
	VPSRLQ   $25, Y9, Y11                \ // ymm11 = ymm9 >> 25 (c)
	VPAND    Y12, Y9, Y9                 \ // ymm9  = ymm9 & low_25_bit_mask
	VPAND    Y13, Y11, Y10               \ // ymm10 = ymm11 & low_26_bit_mask (c0)
	VPSRLQ   $26, Y11, Y11               \ // ymm11 = ymm11 >> 26 (c1)
	                                     \
	VPMULUDQ Y14, Y10, Y10               \ // ymm10 *= v19
	VPMULUDQ Y14, Y11, Y11               \ // ymm11 *= v19
	                                     \
	VPADDQ   Y0, Y10, Y0                 \ // ymm0 += ymm10
	VPADDQ   Y1, Y11, Y1                 \ // ymm1 += ymm11
	                                     \
	VPSRLQ   $26, Y0, Y10                \ // ymm10 = ymm0 >> 26
	VPADDQ   Y1, Y10, Y1                 \ // ymm1  = ymm1 + (ymm0 >> 26)
	VPAND    Y13, Y0, Y0                 \ // ymm0  = ymm0 & low_26_bit_mask
	                                     \
	repack_pair(Y0, Y1)                  \
	repack_pair(Y2, Y3)                  \
	repack_pair(Y4, Y5)                  \
	repack_pair(Y6, Y7)                  \
	repack_pair(Y8, Y9)                  \
	                                     \
	VMOVDQU  Y0, 0(AX)                   \
	VMOVDQU  Y2, 32(AX)                  \
	VMOVDQU  Y4, 64(AX)                  \
	VMOVDQU  Y6, 96(AX)                  \
	VMOVDQU  Y8, 128(AX)                 \

// unpack_fe unpacks a vector of 32-bit lanes into 64-bit lanes.
//
// Inputs:   (gp reg)
// Clobbers: ymm15
// Outputs:  ymm0 .. ymm9
#define unpack_vec(base) \
	VPXOR      Y15, Y15, Y15 \ // y15 = 0
	VMOVDQU    0(base), Y0   \
	VMOVDQU    32(base), Y2  \
	VMOVDQU    64(base), Y4  \
	VMOVDQU    96(base), Y6  \
	VMOVDQU    128(base), Y8 \
	                         \
	VPUNPCKHDQ Y15, Y0, Y1   \ // ymm0, ymm1 = unpack_pair(fe[0])
	VPUNPCKLDQ Y15, Y0, Y0   \
	VPUNPCKHDQ Y15, Y2, Y3   \ // ymm2, ymm3 = unpack_pair(fe[1])
	VPUNPCKLDQ Y15, Y2, Y2   \
	VPUNPCKHDQ Y15, Y4, Y5   \ // ymm4, ymm5 = unpack_pair(fe[2])
	VPUNPCKLDQ Y15, Y4, Y4   \
	VPUNPCKHDQ Y15, Y6, Y7   \ // ymm6, ymm7 = unpack_pair(fe[3])
	VPUNPCKLDQ Y15, Y6, Y6   \
	VPUNPCKHDQ Y15, Y8, Y9   \ // ymm8, ymm9 = unpack_pair(fe[4])
	VPUNPCKLDQ Y15, Y8, Y8   \

// With the way they are currently written, both feMul_AVX2 and
// feSquareAndNegateD_AVX2 need to spill at least one set of unpacked
// pairs onto the stack.  Define some macros for readability.
//
// Note: Instead of rbp, rdi is used as the register containing the
// base of the 64 byte aligned stack.

#define X_0 160(DI)
#define X_1 192(DI)
#define X_2 224(DI)
#define X_3 256(DI)
#define X_4 288(DI)
#define X_5 320(DI)
#define X_6 352(DI)
#define X_7 384(DI)
#define X_8 416(DI)
#define X_9 448(DI)

#define spill_x() \
	VMOVDQA Y0, X_0 \
	VMOVDQA Y1, X_1 \
	VMOVDQA Y2, X_2 \
	VMOVDQA Y3, X_3 \
	VMOVDQA Y4, X_4 \
	VMOVDQA Y5, X_5 \
	VMOVDQA Y6, X_6 \
	VMOVDQA Y7, X_7 \
	VMOVDQA Y8, X_8 \
	VMOVDQA Y9, X_9 \

#define Y_0 480(DI)
#define Y_1 512(DI)
#define Y_2 544(DI)
#define Y_3 576(DI)
#define Y_4 608(DI)
#define Y_5 640(DI)
#define Y_6 672(DI)
#define Y_7 704(DI)
#define Y_8 736(DI)
#define Y_9 768(DI)

#define spill_y() \
	VMOVDQA Y0, Y_0 \
	VMOVDQA Y1, Y_1 \
	VMOVDQA Y2, Y_2 \
	VMOVDQA Y3, Y_3 \
	VMOVDQA Y4, Y_4 \
	VMOVDQA Y5, Y_5 \
	VMOVDQA Y6, Y_6 \
	VMOVDQA Y7, Y_7 \
	VMOVDQA Y8, Y_8 \
	VMOVDQA Y9, Y_9 \

// func vecMul_AVX2(out, a, b *fieldElement2625x4)
TEXT ·vecMul_AVX2(SB), $992-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	// Align the stack on a 64 byte boundary.
	MOVQ SP, DI
	ADDQ $64, DI
	ANDQ $-64, DI

	// ymm0, ymm2, ymm4, ymm6, ymm9 = a
	// 160(DI) .. = ymm0 .. ymm9 (x0 .. x9)
	unpack_vec(BX)
	spill_x()

	// ymm0, ymm2, ymm4, ymm6, ymm9 = b
	// 480(DI) .. = ymm0 .. ymm9 (y0 .. y9)
	unpack_vec(CX)
	spill_y()

	// Precompute some intermediate values.
#define Y_2_19 800(DI)
#define Y_3_19 832(DI)
#define Y_4_19 864(DI)
#define Y_5_19 Y11
#define Y_6_19 Y12
#define Y_7_19 Y13
#define Y_8_19 Y14
#define Y_9_19 Y15
	VMOVDQA  ·v19<>(SB), Y15 // ymm15 <- v19
	VPMULUDQ Y1, Y15, Y1     // ymm1 = y1 * 19
	VPMULUDQ Y2, Y15, Y2     // ymm2 = y2 * 19
	VPMULUDQ Y3, Y15, Y3     // ymm3 = y3 * 19
	VPMULUDQ Y4, Y15, Y4     // ymm4 = y4 * 19
	VPMULUDQ Y5, Y15, Y_5_19 // ymm11 = y5 * 19
	VPMULUDQ Y6, Y15, Y_6_19 // ymm12 = y6 * 19
	VPMULUDQ Y7, Y15, Y_7_19 // ymm13 = y7 * 19
	VPMULUDQ Y8, Y15, Y_8_19 // ymm14 = y8 * 19
	VPMULUDQ Y9, Y15, Y_9_19 // ymm15 = y9 * 19
	VMOVDQA  Y2, Y_2_19
	VMOVDQA  Y3, Y_3_19
	VMOVDQA  Y4, Y_4_19

	//
	// Handle the even zs.
	//
#define add_evens() \
	VPADDQ Y0, Y1, Y0 \
	VPADDQ Y2, Y3, Y2 \
	VPADDQ Y4, Y5, Y4 \
	VPADDQ Y6, Y7, Y6 \
	VPADDQ Y8, Y9, Y8 \

	// z0 = m(x9_2,y1_19)
	// z2 = m(x9_2,y3_19)
	// z4 = m(x9_2,y5_19)
	// z6 = m(x9_2,y7_19)
	// z8 = m(x9_2,y9_19)
	VMOVDQA  X_9, Y10        // ymm10 = x9
	VPADDD   Y10, Y10, Y10   // ymm10 = x9_2
	VPMULUDQ Y1, Y10, Y0     // ymm0 = m(x9_2,y1_19)
	VPMULUDQ Y3, Y10, Y2     // ymm2 = m(x9_2,y3_19)
	VPMULUDQ Y_5_19, Y10, Y4 // ymm4 = m(x9_2,y5_19)
	VPMULUDQ Y_7_19, Y10, Y6 // ymm6 = m(x9_2,y7_19)
	VPMULUDQ Y_9_19, Y10, Y8 // ymm8 = m(x9_2,y9_19)

	// z0 += m(x8,y2_19)
	// z2 += m(x8,y4_19)
	// z4 += m(x8,y6_19)
	// z6 += m(x8,y8_19)
	// z8 += m(x8,y0)
	VMOVDQA  X_8, Y10        // ymm10 = x8
	VPMULUDQ Y_2_19, Y10, Y1 // ymm1 = m(x8,y2_19)
	VPMULUDQ Y_4_19, Y10, Y3 // ymm3 = m(x8,y4_19)
	VPMULUDQ Y_6_19, Y10, Y5 // ymm5 = m(x8,y6_19)
	VPMULUDQ Y_8_19, Y10, Y7 // ymm7 = m(x8,y8_19)
	VPMULUDQ Y_0, Y10, Y9    // ymm9 = m(x8,y0)
	add_evens()

	// z0 += m(x7_2,y3_19)
	// z2 += m(x7_2,y5_19)
	// z4 += m(x7_2,y7_19)
	// z6 += m(x7_2,y9_19)
	// z8 += m(x7_2,y1)
	VMOVDQA  X_7, Y10        // ymm10 = x7
	VPADDD   Y10, Y10, Y10   // ymm10 = x7_2
	VPMULUDQ Y_3_19, Y10, Y1 // ymm1 = m(x7_2,y3_19)
	VPMULUDQ Y_5_19, Y10, Y3 // ymm3 = m(x7_2,y5_19)
	VPMULUDQ Y_7_19, Y10, Y5 // ymm5 = m(x7_2,y7_19)
	VPMULUDQ Y_9_19, Y10, Y7 // ymm7 = m(x7_2,y9_19)
	VPMULUDQ Y_1, Y10, Y9    // ymm9 = m(x7_2,y1)
	add_evens()

	// z0 += m(x6,y4_19)
	// z2 += m(x6,y6_19)
	// z4 += m(x6,y8_19)
	// z6 += m(x6,y0)
	// z8 += m(x6,y2)
	VMOVDQA  X_6, Y10        // ymm10 = x6
	VPMULUDQ Y_4_19, Y10, Y1 // ymm1 = m(x6,y4_19)
	VPMULUDQ Y_6_19, Y10, Y3 // ymm3 = m(x6,y6_19)
	VPMULUDQ Y_8_19, Y10, Y5 // ymm5 = m(x6,y8_19)
	VPMULUDQ Y_0, Y10, Y7    // ymm7 = m(x6,y0)
	VPMULUDQ Y_2, Y10, Y9    // ymm9 = m(x6,y2)
	add_evens()

	// z0 += m(x5_2,y5_19)
	// z2 += m(x5_2,y7_19)
	// z4 += m(x5_2,y9_19)
	// z6 += m(x5_2,y1)
	// z8 += m(x5_2,y3)
	VMOVDQA  X_5, Y10        // ymm10 = x5
	VPADDD   Y10, Y10, Y10   // ymm10 = x5_2
	VPMULUDQ Y_5_19, Y10, Y1 // ymm1 = m(x5_2,y5_19)
	VPMULUDQ Y_7_19, Y10, Y3 // ymm3 = m(x5_2,y7_19)
	VPMULUDQ Y_9_19, Y10, Y5 // ymm5 = m(x5_2,y9_19)
	VPMULUDQ Y_1, Y10, Y7    // ymm7 = m(x5_2,y1)
	VPMULUDQ Y_3, Y10, Y9    // ymm9 = m(x5_2,y3)
	add_evens()

	// z0 += m(x4,y6_19)
	// z2 += m(x4,y8_19)
	// z4 += m(x4,y0)
	// z6 += m(x4,y2)
	// z8 += m(x4,y4)
	VMOVDQA  X_4, Y10        // ymm10 = x4
	VPMULUDQ Y_6_19, Y10, Y1 // ymm1 = m(x4,y6_19)
	VPMULUDQ Y_8_19, Y10, Y3 // ymm3 = m(x4,y8_19)
	VPMULUDQ Y_0, Y10, Y5    // ymm5 = m(x4,y0)
	VPMULUDQ Y_2, Y10, Y7    // ymm7 = m(x4,y2)
	VPMULUDQ Y_4, Y10, Y9    // ymm9 = m(x4,y4)
	add_evens()

	// z0 += m(x3_2,y7_19)
	// z2 += m(x3_2,y9_19)
	// z4 += m(x3_2,y1)
	// z6 += m(x3_2,y3)
	// z8 += m(x3_2,y5)
	VMOVDQA  X_3, Y10        // ymm10 = x3
	VPADDD   Y10, Y10, Y10   // ymm10 = x3_2
	VPMULUDQ Y_7_19, Y10, Y1 // ymm1 = m(x3_2,y7_19)
	VPMULUDQ Y_9_19, Y10, Y3 // ymm3 = m(x3_2,y9_19)
	VPMULUDQ Y_1, Y10, Y5    // ymm5 = m(x3_2,y1)
	VPMULUDQ Y_3, Y10, Y7    // ymm7 = m(x3_2,y3)
	VPMULUDQ Y_5, Y10, Y9    // ymm9 = m(x3_2,y5)
	add_evens()

	// z0 += m(x2,y8_19)
	// z2 += m(x2,y0)
	// z4 += m(x2,y2)
	// z6 += m(x2,y4)
	// z8 += m(x2,y6)
	VMOVDQA  X_2, Y10        // ymm10 = x2
	VPMULUDQ Y_8_19, Y10, Y1 // ymm1 = m(x2,y8_19)
	VPMULUDQ Y_0, Y10, Y3    // ymm3 = m(x2,y0)
	VPMULUDQ Y_2, Y10, Y5    // ymm5 = m(x2,y2)
	VPMULUDQ Y_4, Y10, Y7    // ymm7 = m(x2,y4)
	VPMULUDQ Y_6, Y10, Y9    // ymm9 = m(x2,y6)
	add_evens()

	// z0 += m(x1_2,y9_19)
	// z2 += m(x1_2,y1)
	// z4 += m(x1_2,y3)
	// z6 += m(x1_2,y5)
	// z8 += m(x1_2,y7)
	VMOVDQA  X_1, Y10        // ymm10 = x1
	VPADDD   Y10, Y10, Y10   // ymm10 = x1_2
	VPMULUDQ Y_9_19, Y10, Y1 // ymm1 = m(x1_2,y9_19)
	VPMULUDQ Y_1, Y10, Y3    // ymm3 = m(x1_2,y1)
	VPMULUDQ Y_3, Y10, Y5    // ymm5 = m(x1_2,y3)
	VPMULUDQ Y_5, Y10, Y7    // ymm7 = m(x1_2,y5)
	VPMULUDQ Y_7, Y10, Y9    // ymm9 = m(x1_2,y7)
	add_evens()

	// z0 += m(x0,y0)
	// z2 += m(x0,y2)
	// z4 += m(x0,y4)
	// z6 += m(x0,y6)
	// z8 += m(x0,y8)
	VMOVDQA  X_0, Y10     // ymm10 = x0
	VPMULUDQ Y_0, Y10, Y1 // ymm1 = m(x0,y0)
	VPMULUDQ Y_2, Y10, Y3 // ymm3 = m(x0,y2)
	VPMULUDQ Y_4, Y10, Y5 // ymm5 = m(x0,y4)
	VPMULUDQ Y_6, Y10, Y7 // ymm7 = m(x0,y6)
	VPMULUDQ Y_8, Y10, Y9 // ymm9 = m(x0,y8)
	add_evens()

#undef add_evens

	// At this point, z0, z2, z4, z6, z8 are done, so store them onto the
	// stack to free up registers.
	VMOVDQA Y0, 0(DI)
	VMOVDQA Y2, 32(DI)
	VMOVDQA Y4, 64(DI)
	VMOVDQA Y6, 96(DI)
	VMOVDQA Y8, 128(DI)

	//
	// Handle the odd zs.
	//
#define add_odds() \
	VPADDQ Y1, Y0, Y1 \
	VPADDQ Y3, Y2, Y3 \
	VPADDQ Y5, Y4, Y5 \
	VPADDQ Y7, Y6, Y7 \
	VPADDQ Y9, Y8, Y9 \

	// z1 = m(x9,y2_19)
	// z3 = m(x9,y4_19)
	// z5 = m(x9,y6_19)
	// z7 = m(x9,y8_19)
	// z9 = m(x9,y0)
	VMOVDQA  X_9, Y10        // ymm10 = x9
	VPMULUDQ Y_2_19, Y10, Y1 // ymm1 = m(x9,y2_19)
	VPMULUDQ Y_4_19, Y10, Y3 // ymm3 = m(x9,y4_19)
	VPMULUDQ Y_6_19, Y10, Y5 // ymm5 = m(x9,y6_19)
	VPMULUDQ Y_8_19, Y10, Y7 // ymm7 = m(x9,y8_19)
	VPMULUDQ Y_0, Y10, Y9    // ymm9 = m(x9,y0)

	// z1 += m(x8,y3_19)
	// z3 += m(x8,y5_19)
	// z5 += m(x8,y7_19)
	// z7 += m(x8,y9_19)
	// z9 += m(x8,y1)
	VMOVDQA  X_8, Y10        // ymm10 = x8
	VPMULUDQ Y_3_19, Y10, Y0 // ymm0 = m(x8,y3_19)
	VPMULUDQ Y_5_19, Y10, Y2 // ymm2 = m(x8,y5_19)
	VPMULUDQ Y_7_19, Y10, Y4 // ymm4 = m(x8,y7_19)
	VPMULUDQ Y_9_19, Y10, Y6 // ymm6 = m(x8,y9_19)
	VPMULUDQ Y_1, Y10, Y8    // ymm8 = m(x8,y1)
	add_odds()

	// z1 += m(x7,y4_19)
	// z3 += m(x7,y6_19)
	// z5 += m(x7,y8_19)
	// z7 += m(x7,y0)
	// z9 += m(x7,y2)
	VMOVDQA  X_7, Y10        // ymm10 = x7
	VPMULUDQ Y_4_19, Y10, Y0 // ymm0 = m(x7,y4_19)
	VPMULUDQ Y_6_19, Y10, Y2 // ymm2 = m(x7,y6_19)
	VPMULUDQ Y_8_19, Y10, Y4 // ymm4 = m(x7,y8_19)
	VPMULUDQ Y_0, Y10, Y6    // ymm6 = m(x7,y0)
	VPMULUDQ Y_2, Y10, Y8    // ymm8 = m(x7,y2)
	add_odds()

	// z1 += m(x6,y5_19)
	// z3 += m(x6,y7_19)
	// z5 += m(x6,y9_19)
	// z7 += m(x6,y1)
	// z9 += m(x6,y3)
	VMOVDQA  X_6, Y10        // ymm10 = x6
	VPMULUDQ Y_5_19, Y10, Y0 // ymm0 = m(x6,y5_19)
	VPMULUDQ Y_7_19, Y10, Y2 // ymm2 = m(x6,y7_19)
	VPMULUDQ Y_9_19, Y10, Y4 // ymm4 = m(x6,y9_19)
	VPMULUDQ Y_1, Y10, Y6    // ymm6 = m(x6,y1)
	VPMULUDQ Y_3, Y10, Y8    // ymm8 = m(x6,y3)
	add_odds()

	// z1 += m(x5,y6_19)
	// z3 += m(x5,y8_19)
	// z5 += m(x5,y0)
	// z7 += m(x5,y2)
	// z9 += m(x5,y4)
	VMOVDQA  X_5, Y10        // ymm10 = x5
	VPMULUDQ Y_6_19, Y10, Y0 // ymm0 = m(x5,y6_19)
	VPMULUDQ Y_8_19, Y10, Y2 // ymm2 = m(x5,y8_19)
	VPMULUDQ Y_0, Y10, Y4    // ymm4 = m(x5,y0)
	VPMULUDQ Y_2, Y10, Y6    // ymm6 = m(x5,y2)
	VPMULUDQ Y_4, Y10, Y8    // ymm8 = m(x5,y4)
	add_odds()

	// z1 += m(x4,y7_19)
	// z3 += m(x4,y9_19)
	// z5 += m(x4,y1)
	// z7 += m(x4,y3)
	// z9 += m(x4,y5)
	VMOVDQA  X_4, Y10        // ymm10 = x4
	VPMULUDQ Y_7_19, Y10, Y0 // ymm0 = m(x4,y7_19)
	VPMULUDQ Y_9_19, Y10, Y2 // ymm2 = m(x4,y9_19)
	VPMULUDQ Y_1, Y10, Y4    // ymm4 = m(x4,y1)
	VPMULUDQ Y_3, Y10, Y6    // ymm6 = m(x4,y3)
	VPMULUDQ Y_5, Y10, Y8    // ymm8 = m(x4,y5)
	add_odds()

	// z1 += m(x3,y8_19)
	// z3 += m(x3,y0)
	// z5 += m(x3,y2)
	// z7 += m(x3,y4)
	// z9 += m(x3,y6)
	VMOVDQA  X_3, Y10        // ymm10 = x3
	VPMULUDQ Y_8_19, Y10, Y0 // ymm0 = m(x3,y8_19)
	VPMULUDQ Y_0, Y10, Y2    // ymm2 = m(x3,y0)
	VPMULUDQ Y_2, Y10, Y4    // ymm4 = m(x3,y2)
	VPMULUDQ Y_4, Y10, Y6    // ymm6 = m(x3,y4)
	VPMULUDQ Y_6, Y10, Y8    // ymm8 = m(x3,y6)
	add_odds()

	// z1 += m(x2,y9_19)
	// z3 += m(x2,y1)
	// z5 += m(x2,y3)
	// z7 += m(x2,y5)
	// z9 += m(x2,y7)
	VMOVDQA  X_2, Y10        // ymm10 = x2
	VPMULUDQ Y_9_19, Y10, Y0 // ymm0 = m(x2,y9_19)
	VPMULUDQ Y_1, Y10, Y2    // ymm2 = m(x2,y1)
	VPMULUDQ Y_3, Y10, Y4    // ymm4 = m(x2,y3)
	VPMULUDQ Y_5, Y10, Y6    // ymm6 = m(x2,y5)
	VPMULUDQ Y_7, Y10, Y8    // ymm8 = m(x2,y7)
	add_odds()

	// z1 += m(x1,y0)
	// z3 += m(x1,y2)
	// z5 += m(x1,y4)
	// z7 += m(x1,y6)
	// z9 += m(x1,y8)
	VMOVDQA  X_1, Y10     // ymm10 = x1
	VPMULUDQ Y_0, Y10, Y0 // ymm0 = m(x1,y0)
	VPMULUDQ Y_2, Y10, Y2 // ymm2 = m(x1,y2)
	VPMULUDQ Y_4, Y10, Y4 // ymm4 = m(x1,y4)
	VPMULUDQ Y_6, Y10, Y6 // ymm6 = m(x1,y6)
	VPMULUDQ Y_8, Y10, Y8 // ymm8 = m(x1,y8)
	add_odds()

	// z1 += m(x0,y1)
	// z3 += m(x0,y3)
	// z5 += m(x0,y5)
	// z7 += m(x0,y7)
	// z9 += m(x0,y9)
	VMOVDQA  X_0, Y10     // ymm10 = x0
	VPMULUDQ Y_1, Y10, Y0 // ymm0 = m(x0,y1)
	VPMULUDQ Y_3, Y10, Y2 // ymm2 = m(x0,y3)
	VPMULUDQ Y_5, Y10, Y4 // ymm4 = m(x0,y5)
	VPMULUDQ Y_7, Y10, Y6 // ymm5 = m(x0,y7)
	VPMULUDQ Y_9, Y10, Y8 // ymm8 = m(x0,y9)
	add_odds()

#undef add_odds

#undef Y_2_19
#undef Y_3_19
#undef Y_4_19
#undef Y_5_19
#undef Y_6_19
#undef Y_7_19
#undef Y_8_19
#undef Y_9_19

	// At this point z1, z3, z5, z7, z9 are done, so restore z0, z2, z4,
	// z6, z8 from the stack.
	VMOVDQA 0(DI), Y0
	VMOVDQA 32(DI), Y2
	VMOVDQA 64(DI), Y4
	VMOVDQA 96(DI), Y6
	VMOVDQA 128(DI), Y8

	reduce64()

	VZEROUPPER
	RET

// func vecSquareAndNegateD_AVX2(out *fieldElement2625x4)
TEXT ·vecSquareAndNegateD_AVX2(SB), NOSPLIT, $544-8
	MOVQ out+0(FP), AX

	// Align the stack on a 64 byte boundary.
	MOVQ SP, DI
	ADDQ $64, DI
	ANDQ $-64, DI

	// ymm0, ymm2, ymm4, ymm6, ymm8 = out (x0 .. x9)
	// 160(DI) .. = ymm0 .. ymm9 (x0 .. x9)
	unpack_vec(AX)
	spill_x()

	// Precompute some intermediate values.
#define V_19 Y15
#define X_1_2 Y11
#define X_3_2 Y12
#define X_5_2 Y13
#define X_7_2 Y14
	VMOVDQA ·v19<>(SB), V_19 // ymm15 <- v19
	VPADDD  Y1, Y1, X_1_2    // ymm11 = x1_2
	VPADDD  Y3, Y3, X_3_2    // ymm12 = x3_2
	VPADDD  Y5, Y5, X_5_2    // ymm13 = x5_2
	VPADDD  Y7, Y7, X_7_2    // ymm14 = x7_2

	// z0 = m(x1_2,x9_19)
	// z1 = m(x2,x9_19)
	// z2 = m(x3_2,x9_19)
	// z3 = m(x4,x9_19)
	// z4 = m(x5_2,x9_19)
	// z5 = m(x6,x9_19)
	// z6 = m(x7_2,x9_19)
	// z7 = m(x8,x9_19)
	// z8 = m(x9,x9_19)
	VPMULUDQ V_19, Y9, Y10  // ymm10 = x9_19
	VPMULUDQ X_1_2, Y10, Y0 // ymm0 = m(x1_2,x9_19)
	VPMULUDQ Y2, Y10, Y1    // ymm1 = m(x2,x9_19)
	VPMULUDQ Y12, Y10, Y2   // ymm2 = m(x3_2,x9_19)
	VPMULUDQ Y4, Y10, Y3    // ymm3 = m(x4,x9_19)
	VPMULUDQ X_5_2, Y10, Y4 // ymm4 = m(x5_2,x9_19)
	VPMULUDQ Y6, Y10, Y5    // ymm5 = m(x6,x9_19)
	VPMULUDQ X_7_2, Y10, Y6 // ymm6 = m(x7_2,x9_19)
	VPMULUDQ Y8, Y10, Y7    // ymm7 = m(x8,x9_19)
	VPMULUDQ Y9, Y10, Y8    // ymm8 = m(x9,x9_19)

	// z5 .. z8 <<= 1
	VPADDQ  Y5, Y5, Y5 // ymm5 <<= 1
	VPADDQ  Y6, Y6, Y6 // ymm6 <<= 1
	VPADDQ  Y7, Y7, Y7 // ymm7 <<= 1
	VPADDQ  Y8, Y8, Y8 // ymm8 <<= 1
	VMOVDQA Y5, 0(DI)
	VMOVDQA Y6, 32(DI)
	VMOVDQA Y7, 64(DI)
	VMOVDQA Y8, 96(DI)

	// z0 += m(x3_2,x7_19)
	// z1 += m(x4,x7_19)
	// z2 += m(x5_2,x7_19)
	// z3 += m(x6,x7_19)
	// z4 += m(x7,x7_19)
	VMOVDQA  X_7, Y9        // ymm9 = x7
	VPMULUDQ V_19, Y9, Y10  // ymm10 = x7_19
	VPMULUDQ Y12, Y10, Y5   // ymm5 = m(x3_2,x7_19)
	VPMULUDQ X_4, Y10, Y6   // ymm6 = m(x4,x7_19)
	VPMULUDQ X_5_2, Y10, Y7 // ymm7 = m(x5_2,x7_19)
	VPMULUDQ X_6, Y10, Y8   // ymm8 = m(x6,x7_19)
	VPMULUDQ Y9, Y10, Y9    // ymm9 = m(x7,x7_19)
	VPADDQ   Y0, Y5, Y0
	VPADDQ   Y1, Y6, Y1
	VPADDQ   Y2, Y7, Y2
	VPADDQ   Y3, Y8, Y3
	VPADDQ   Y4, Y9, Y4

	// z0 += m(x5,x5_19)
	VMOVDQA  X_5, Y10      // ymm10 = x5
	VPMULUDQ V_19, Y10, Y9 // ymm9 = x5_19
	VPMULUDQ Y10, Y9, Y9   // ymm9 = m(x5,x5_19)
	VPADDQ   Y0, Y9, Y0

	// z0 .. z4 <<= 1
	VPADDQ Y0, Y0, Y0 // ymm0 <<= 1
	VPADDQ Y1, Y1, Y1 // ymm1 <<= 1
	VPADDQ Y2, Y2, Y2 // ymm2 <<= 1
	VPADDQ Y3, Y3, Y3 // ymm3 <<= 1
	VPADDQ Y4, Y4, Y4 // ymm4 <<= 1

	// At this point:
	// z0 = ((m(x1_2,x9_19) + m(x3_2,x7_19) + m(x5,x5_19)) << 1)
	// z1 = ((m(x2,x9_19)   + m(x4,x7_19))                 << 1)
	// z2 = ((m(x3_2,x9_19) + m(x5_2,x7_19))               << 1)
	// z3 = ((m(x4,x9_19)   + m(x6,x7_19))                 << 1)
	// z4 = ((m(x5_2,x9_19) + m(x7,x7_19))                 << 1)
	// z5 = ((m(x6,x9_19))                                 << 1)
	// z6 = ((m(x7_2,x9_19))                               << 1)
	// z7 = ((m(x8,x9_19))                                 << 1)
	// z8 = ((m(x9,x9_19))                                 << 1)
	// z9 = undefined

	// z2 += m(x6,x6_19)
	// z4 += m(x6_2,x8_19)
	VMOVDQA  X_6, Y5        // ymm5 = x6
	VPMULUDQ X_8, V_19, Y10 // ymm10 = x8_19
	VPMULUDQ Y5, V_19, Y9   // ymm9 = x6_19
	VPADDD   Y5, Y5, Y6     // ymm6 = x6_2
	VPMULUDQ Y5, Y9, Y5     // ymm5 = m(x6,x6_19)
	VPMULUDQ Y6, Y10, Y6    // ymm6 = m(x6_2,x8_19)
	VPADDQ   Y2, Y5, Y2
	VPADDQ   Y4, Y6, Y4

#undef V_19

	// z0 += m(x4_2,x6_19)
	// z2 += m(x4_2,x8_19)
	// z1 += m(x5_2,x6_19)
	// z3 += m(x5_2,x8_19)
	VMOVDQA  X_4, Y7        // ymm7 = x4
	VPADDQ   Y7, Y7, Y7     // ymm7 = x4_2
	VPMULUDQ X_5_2, Y9, Y5  // ymm5 = m(x5_2,x6_19)
	VPMULUDQ X_5_2, Y10, Y6 // ymm6 = m(x5_2,x8_19)
	VPMULUDQ Y7, Y10, Y8    // ymm8 = m(x4_2,x8_19)
	VPMULUDQ Y7, Y9, Y7     // ymm7 = m(x4_2,x6_19) (Last use of ymm9 = x6_19)
	VPADDQ   Y1, Y5, Y1
	VPADDQ   Y3, Y6, Y3
	VPADDQ   Y0, Y7, Y0
	VPADDQ   Y2, Y8, Y2

	// z0 += m(x2_2,x8_19)
	// z1 += m(x3_2,x8_19)
	// z4 += m(x2,x2)
	VMOVDQA  X_2, Y15       // ymm15 = x2
	VPADDD   Y15, Y15, Y5   // ymm5 = x2_2
	VPMULUDQ Y5, Y10, Y5    // ymm5 = m(x2_2,x8_19)
	VPMULUDQ X_3_2, Y10, Y6 // ymm6 = m(x3_2,x8_19)
	VPMULUDQ Y15, Y15, Y7   // ymm7 = m(x2,x2)
	VPADDQ   Y0, Y5, Y0
	VPADDQ   Y1, Y6, Y1
	VPADDQ   Y4, Y7, Y4

	// z2 += m(x1_2,x1)
	// z3 += m(x1_2,x2)
	// z4 += m(x1_2,x3_2)
	VPMULUDQ X_1, X_1_2, Y5   // ymm5 = m(x1_2,x1)
	VPMULUDQ Y15, X_1_2, Y6   // ymm6 = m(x1_2,x2)
	VPMULUDQ X_3_2, X_1_2, Y7 // ymm7 = m(x1_2,x3_2)
	VPADDQ   Y2, Y5, Y2
	VPADDQ   Y3, Y6, Y3
	VPADDQ   Y4, Y7, Y4

	// z0 += m(x0,x0)
	// z1 += m(x0_2,x1)
	// z2 += m(x0_2,x2)
	// z3 += m(x0_2,x3)
	// z4 += m(x0_2,x4)
	VMOVDQA  X_0, Y5      // ymm5 = x0
	VPADDD   Y5, Y5, Y9   // ymm9 = x0_2
	VPMULUDQ Y5, Y5, Y5   // ymm5 = m(x0,x0)
	VPMULUDQ X_1, Y9, Y6  // ymm6 = m(x0_2,x1)
	VPMULUDQ Y15, Y9, Y7  // ymm7 = m(x0_2,x2)
	VPMULUDQ X_3, Y9, Y8  // ymm9 = m(x0_2,x3)
	VPMULUDQ X_4, Y9, Y15 // ymm15 = m(x0_2,x4) (Rather preserve x0_2 than x2)
	VPADDQ   Y0, Y5, Y0
	VPADDQ   Y1, Y6, Y1
	VPADDQ   Y2, Y7, Y2
	VPADDQ   Y3, Y8, Y3
	VPADDQ   Y4, Y15, Y4

	// z5 += m(x0_2,x5)
	// z6 += m(x0_2,x6)
	// z7 += m(x0_2,x7)
	// z8 += m(x0_2,x8)
	// z9 = m(x0_2,x9)
	VPMULUDQ X_5, Y9, Y5    // ymm5 = m(x0_2,x5)
	VPMULUDQ X_6, Y9, Y6    // ymm6 = m(x0_2,x6)
	VPMULUDQ X_7, Y9, Y7    // ymm7 = m(x0_2,x7)
	VPMULUDQ X_8, Y9, Y8    // ymm8 = m(x0_2,x8)
	VPMULUDQ X_9, Y9, Y9    // ymm9 = m(x0_2,x9)
	VPADDQ   0(DI), Y5, Y5
	VPADDQ   32(DI), Y6, Y6
	VPADDQ   64(DI), Y7, Y7
	VPADDQ   96(DI), Y8, Y8

	// At this point, z0 .. z4 are done, and we no longer need z5 .. z8
	// that we previously stored onto the stack, so store z0 .. z4 to
	// free up registers.
	VMOVDQA Y0, 0(DI)
	VMOVDQA Y1, 32(DI)
	VMOVDQA Y2, 64(DI)
	VMOVDQA Y3, 96(DI)
	VMOVDQA Y4, 128(DI)

	// z5 += m(x1_2,x4)
	// z6 += m(x1_2,x5_2)
	// z7 += m(x1_2,x6)
	// z8 += m(x1_2,x7_2)
	// z9 += m(x1_2,x8)
	VPMULUDQ X_4, X_1_2, Y0   // ymm0 = m(x1_2,x4)
	VPMULUDQ X_5_2, X_1_2, Y1 // ymm1 = m(x1_2,x5_2)
	VPMULUDQ X_6, X_1_2, Y2   // ymm2 = m(x1_2,x6)
	VPMULUDQ X_7_2, X_1_2, Y3 // ymm3 = m(x1_2,x7_2)
	VPMULUDQ X_8, X_1_2, Y4   // ymm4 = m(x1_2,x8)
	VPADDQ   Y5, Y0, Y5
	VPADDQ   Y6, Y1, Y6
	VPADDQ   Y7, Y2, Y7
	VPADDQ   Y8, Y3, Y8
	VPADDQ   Y9, Y4, Y9

#undef X_1_2

	// z5 += m(x2_2,x3)
	// z6 += m(x2_2,x4)
	// z7 += m(x2_2,x5)
	// z8 += m(x2_2,x6)
	// z9 += m(x2_2,x7)
	VMOVDQA  X_4, Y11      // ymm11 = x4
	VMOVDQA  X_2, Y15      // ymm15 = x2
	VPADDD   Y15, Y15, Y15 // ymm15 = x2_2
	VPMULUDQ X_3, Y15, Y0  // ymm0 = m(x2_2,x3)
	VPMULUDQ Y11, Y15, Y1  // ymm1 = m(x2_2,x4)
	VPMULUDQ X_5, Y15, Y2  // ymm2 = m(x2_2,x5)
	VPMULUDQ X_6, Y15, Y3  // ymm3 = m(x2_2,x6)
	VPMULUDQ X_7, Y15, Y4  // ymm4 = m(x2_2,x7)
	VPADDQ   Y5, Y0, Y5
	VPADDQ   Y6, Y1, Y6
	VPADDQ   Y7, Y2, Y7
	VPADDQ   Y8, Y3, Y8
	VPADDQ   Y9, Y4, Y9

	// z6 += m(x3_2,x3)
	// z7 += m(x3_2,x4)
	// z8 += m(x3_2,x5_2)
	// z9 += m(x3_2,x6)
	VPMULUDQ X_3, X_3_2, Y0   // ymm0 = m(x3_2,x3)
	VPMULUDQ Y11, X_3_2, Y1   // ymm1 = m(x3_2,x4)
	VPMULUDQ X_5_2, X_3_2, Y2 // ymm2 = m(x3_2,x5_2)
	VPMULUDQ X_6, X_3_2, Y3   // ymm3 = m(x3_2,x6)
	VPADDQ   Y6, Y0, Y6
	VPADDQ   Y7, Y1, Y7
	VPADDQ   Y8, Y2, Y8
	VPADDQ   Y9, Y3, Y9

#undef X_5_2
#undef X_3_2

	// z5 += m(x7_2,x8_19)
	// z6 += m(x8,x8_19)
	// z8 += m(x4,x4)
	// z9 += m(x4_2,x5)
	VPADDD   Y11, Y11, Y15  // ymm15 = x4_2
	VPMULUDQ X_7_2, Y10, Y0 // ymm0 = m(x7_2,x8_19)
	VPMULUDQ X_8, Y10, Y1   // ymm1 = m(x8,x8_19) (Last use of ymm10 = x8_19)
	VPMULUDQ Y11, Y11, Y2   // ymm2 = m(x4,x4)
	VPMULUDQ X_5, Y15, Y3   // ymm3 = m(x4_2,x5)
	VPADDQ   Y5, Y0, Y5
	VPADDQ   Y6, Y1, Y6
	VPADDQ   Y8, Y2, Y8
	VPADDQ   Y9, Y3, Y9

#undef X_7_2

	// At this point z5 .. z9 are done, so restore z0 .. z4 from the stack.
	VMOVDQA 0(DI), Y0
	VMOVDQA 32(DI), Y1
	VMOVDQA 64(DI), Y2
	VMOVDQA 96(DI), Y3
	VMOVDQA 128(DI), Y4

	// At this point ymm0 .. ymm9 contains the final z0 .. z9, prior
	// to negating d.
	VMOVDQA ·low_p_37<>(SB), Y10  // ymm10 <- low_p_37
	VMOVDQA ·even_p_37<>(SB), Y14 // ymm14 <- even_p_37
	VMOVDQA ·odd_p_37<>(SB), Y15  // ymm15 <- odd_p_37

	VPSUBQ Y0, Y10, Y10 // ymm10 = low_p_37 - z0
	VPSUBQ Y2, Y14, Y11 // ymm11 = even_p_37 - z2
	VPSUBQ Y4, Y14, Y12 // ymm12 = even_p_37 - z4
	VPSUBQ Y6, Y14, Y13 // ymm13 = even_p_37 - z6
	VPSUBQ Y8, Y14, Y14 // ymm14 = even_p_37 - z8

	VPBLENDD LANES_D64, Y10, Y0, Y0 // y0 = blend(z0, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y11, Y2, Y2 // y2 = blend(z2, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y12, Y4, Y4 // y4 = blend(z4, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y13, Y6, Y6 // y6 = blend(z6, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y14, Y8, Y8 // y8 = blend(z8, p-x, D_LANES64)

	VPSUBQ Y1, Y15, Y10 // ymm10 = odd_p_37 - z1
	VPSUBQ Y3, Y15, Y11 // ymm11 = odd_p_37 - z3
	VPSUBQ Y5, Y15, Y12 // ymm12 = odd_p_37 - z5
	VPSUBQ Y7, Y15, Y13 // ymm13 = odd_p_37 - z7
	VPSUBQ Y9, Y15, Y14 // ymm14 = odd_p_37 - z9

	VPBLENDD LANES_D64, Y10, Y1, Y1 // y1 = blend(z1, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y11, Y3, Y3 // y3 = blend(z3, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y12, Y5, Y5 // y5 = blend(z5, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y13, Y7, Y7 // y7 = blend(z7, p-x, D_LANES64)
	VPBLENDD LANES_D64, Y14, Y9, Y9 // y9 = blend(z9, p-x, D_LANES64)

	reduce64()

	VZEROUPPER
	RET

#undef spill_x
#undef X_0
#undef X_1
#undef X_2
#undef X_3
#undef X_4
#undef X_5
#undef X_6
#undef X_7
#undef X_8
#undef X_9

#undef spill_y
#undef Y_0
#undef Y_1
#undef Y_2
#undef Y_3
#undef Y_4
#undef Y_5
#undef Y_6
#undef Y_7
#undef Y_8
#undef Y_9

// func vecDoubleExtended_Step1_AVX2(out *fieldElement2625x4, vec *extendedPoint)
TEXT ·vecDoubleExtended_Step1_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ out+0(FP), AX
	MOVQ vec+8(FP), BX

	// ymm0 .. ymm4 = vec
	load_vec(BX)

	// ymm5 .. ymm9 = self.0.shuffle(Shuffle::ABAB) (tmp0)
	VPERMQ SHUFFLE_ABAB, Y0, Y5
	VPERMQ SHUFFLE_ABAB, Y1, Y6
	VPERMQ SHUFFLE_ABAB, Y2, Y7
	VPERMQ SHUFFLE_ABAB, Y3, Y8
	VPERMQ SHUFFLE_ABAB, Y4, Y9

	// ymm10 .. ymm14 = tmp0.shuffle(Shuffle::BADC) (tmp1)
	VPSHUFD SHUFFLE_BADC, Y5, Y10
	VPSHUFD SHUFFLE_BADC, Y6, Y11
	VPSHUFD SHUFFLE_BADC, Y7, Y12
	VPSHUFD SHUFFLE_BADC, Y8, Y13
	VPSHUFD SHUFFLE_BADC, Y9, Y14

	// y5 .. y9 = tmp0 + tmp1
	VPADDD Y5, Y10, Y5
	VPADDD Y6, Y11, Y6
	VPADDD Y7, Y12, Y7
	VPADDD Y8, Y13, Y8
	VPADDD Y9, Y14, Y9

	// ymm0 .. ymm4 = self.0.blend(tmp0 + tmp1, Lanes::D)
	VPBLENDD LANES_D, Y5, Y0, Y0
	VPBLENDD LANES_D, Y6, Y1, Y1
	VPBLENDD LANES_D, Y7, Y2, Y2
	VPBLENDD LANES_D, Y8, Y3, Y3
	VPBLENDD LANES_D, Y9, Y4, Y4

	// out = ymm0 .. ymm4
	store_vec(AX)

	VZEROUPPER
	RET

// func vecDoubleExtended_Step2_AVX2(tmp0, tmp1 *fieldElement2625x4)
TEXT ·vecDoubleExtended_Step2_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ tmp0+0(FP), AX
	MOVQ tmp1+8(FP), BX

	VPXOR Y15, Y15, Y15

	// ymm5 .. ymm9 = tmp1
	VMOVDQU 0(BX), Y5
	VMOVDQU 32(BX), Y6
	VMOVDQU 64(BX), Y7
	VMOVDQU 96(BX), Y8
	VMOVDQU 128(BX), Y9

	// ymm10 .. ymm14 = tmp1 + tmp1
	VPADDD Y5, Y5, Y10
	VPADDD Y6, Y6, Y11
	VPADDD Y7, Y7, Y12
	VPADDD Y8, Y8, Y13
	VPADDD Y9, Y9, Y14

	// ymm0 .. ymm4 = zero.blend(tmp1 + tmp1, Lanes::C) (tmp0)
	VPBLENDD LANES_C, Y10, Y15, Y0
	VPBLENDD LANES_C, Y11, Y15, Y1
	VPBLENDD LANES_C, Y12, Y15, Y2
	VPBLENDD LANES_C, Y13, Y15, Y3
	VPBLENDD LANES_C, Y14, Y15, Y4

	// ymm5 .. ymm9 = tmp0.blend(tmp1, Lanes::D) (tmp0)
	VPBLENDD LANES_D, Y5, Y0, Y0
	VPBLENDD LANES_D, Y6, Y1, Y1
	VPBLENDD LANES_D, Y7, Y2, Y2
	VPBLENDD LANES_D, Y8, Y3, Y3
	VPBLENDD LANES_D, Y9, Y4, Y4

	// ymm10 .. ymm14 = tmp1.shuffle(Shuffle::AAAA) (S_1)
	VMOVDQA ·shuffle_AAAA<>(SB), Y14
	VPERMD  Y5, Y14, Y10
	VPERMD  Y6, Y14, Y11
	VPERMD  Y7, Y14, Y12
	VPERMD  Y8, Y14, Y13
	VPERMD  Y9, Y14, Y14

	// ymm0 .. ymm4 = tmp0 + S_1
	VPADDD Y0, Y10, Y0
	VPADDD Y1, Y11, Y1
	VPADDD Y2, Y12, Y2
	VPADDD Y3, Y13, Y3
	VPADDD Y4, Y14, Y4

	// ymm10 .. ymm14 = tmp1.shuffle(Shuffle::BBBB) (S_2)
	VMOVDQA ·shuffle_BBBB<>(SB), Y14
	VPERMD  Y5, Y14, Y10
	VPERMD  Y6, Y14, Y11
	VPERMD  Y7, Y14, Y12
	VPERMD  Y8, Y14, Y13
	VPERMD  Y9, Y14, Y14

	// ymm5 .. ymm9 = zero.blend(S_2, Lanes::AD)
	VPBLENDD LANES_AD, Y10, Y15, Y5
	VPBLENDD LANES_AD, Y11, Y15, Y6
	VPBLENDD LANES_AD, Y12, Y15, Y7
	VPBLENDD LANES_AD, Y13, Y15, Y8
	VPBLENDD LANES_AD, Y14, Y15, Y9

	// ymm0 .. ymm4 = tmp0 + zero.blend(S_2, Lanes::AD)
	VPADDD Y0, Y5, Y0
	VPADDD Y1, Y6, Y1
	VPADDD Y2, Y7, Y2
	VPADDD Y3, Y8, Y3
	VPADDD Y4, Y9, Y4

	// ymm10 .. ymm14 = S_2.negate_lazy()
	VMOVDQA ·p_times_2_lo<>(SB), Y9
	VMOVDQA ·p_times_2_hi<>(SB), Y8
	VPSUBD  Y10, Y9, Y10
	VPSUBD  Y11, Y8, Y11
	VPSUBD  Y12, Y8, Y12
	VPSUBD  Y13, Y8, Y13
	VPSUBD  Y14, Y8, Y14

	// ymm5 .. ymm9 = zero.blend(S_2.negate_lazy(), Lanes::BC)
	VPBLENDD LANES_BC, Y10, Y15, Y5
	VPBLENDD LANES_BC, Y11, Y15, Y6
	VPBLENDD LANES_BC, Y12, Y15, Y7
	VPBLENDD LANES_BC, Y13, Y15, Y8
	VPBLENDD LANES_BC, Y14, Y15, Y9

	// ymm0 .. ymm4 = tmp0 + zero.blend(S_2.negate_lazy(), Lanes::BC)
	VPADDD Y0, Y5, Y0
	VPADDD Y1, Y6, Y1
	VPADDD Y2, Y7, Y2
	VPADDD Y3, Y8, Y3
	VPADDD Y4, Y9, Y4

	VMOVDQA ·shuffle_DBBD<>(SB), Y15
	VMOVDQA ·shuffle_CACA<>(SB), Y14

	// ymm5 .. ymm9 = tmp0.shuffle(Shuffle::DBBD)
	VPERMD Y0, Y15, Y5
	VPERMD Y1, Y15, Y6
	VPERMD Y2, Y15, Y7
	VPERMD Y3, Y15, Y8
	VPERMD Y4, Y15, Y9

	// ymm0 .. ymm4 = tmp0.shuffle(Shuffle:CACA)
	VPERMD Y0, Y14, Y0
	VPERMD Y1, Y14, Y1
	VPERMD Y2, Y14, Y2
	VPERMD Y3, Y14, Y3
	VPERMD Y4, Y14, Y4

	// tmp1 = ymm5 .. ymm9
	store_vec_2(BX)

	// tmp0 = ymm0 .. ymm4
	store_vec(AX)

	VZEROUPPER
	RET

// diff_sum computes `(B - A, B + A, D - C, D + C)` over the vector stored
// in ymm0 .. ymm4 and writes the output to ymm5 .. ymm9.
//
// Inputs:   ymm0 .. ymm4
// Clobbers: ymm10 .. ymm15
// Outputs:  ymm5 .. ymm9
#define diff_sum() \
	VMOVDQA  ·p_times_2_lo<>(SB), Y15                                    \ // ymm15 <- P_TIMES_2_LO
	VMOVDQA  ·p_times_2_hi<>(SB), Y14                                    \ // ymm14 <- P_TIMES_2_HI
	                                                                     \
	\ // ymm5 .. ymm9 = self.shuffle(BADC) (tmp1)
	VPSHUFD  SHUFFLE_BADC, Y0, Y5                                        \
	VPSHUFD  SHUFFLE_BADC, Y1, Y6                                        \
	VPSHUFD  SHUFFLE_BADC, Y2, Y7                                        \
	VPSHUFD  SHUFFLE_BADC, Y3, Y8                                        \
	VPSHUFD  SHUFFLE_BADC, Y4, Y9                                        \
	                                                                     \
	\ // ymm10 .. ymm14 = self.negate_lazy()
	VPSUBD   Y0, Y15, Y10                                                \
	VPSUBD   Y1, Y14, Y11                                                \
	VPSUBD   Y2, Y14, Y12                                                \
	VPSUBD   Y3, Y14, Y13                                                \
	VPSUBD   Y4, Y14, Y14                                                \
	                                                                     \
	\ // ymm10 .. ymm14 = self.blend(self.negate_lazy, Lanes::AC) (tmp2)
	VPBLENDD LANES_AC, Y10, Y0, Y10                                      \
	VPBLENDD LANES_AC, Y11, Y1, Y11                                      \
	VPBLENDD LANES_AC, Y12, Y2, Y12                                      \
	VPBLENDD LANES_AC, Y13, Y3, Y13                                      \
	VPBLENDD LANES_AC, Y14, Y4, Y14                                      \
	                                                                     \
	\ // ymm5 .. ymm9 = ymm5 .. ymm9 + ymm10 .. ymm14
	VPADDD   Y5, Y10, Y5                                                 \
	VPADDD   Y6, Y11, Y6                                                 \
	VPADDD   Y7, Y12, Y7                                                 \
	VPADDD   Y8, Y13, Y8                                                 \
	VPADDD   Y9, Y14, Y9                                                 \

// func vecAddSubExtendedCached_Step1_AVX2(out *fieldElement2625x4, vec *extendedPoint)
TEXT ·vecAddSubExtendedCached_Step1_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ out+0(FP), AX
	MOVQ vec+8(FP), BX

	// ymm0 .. ymm4 = vec
	load_vec(BX)

	// ymm5 .. ymm9 = tmp.diff_sum()
	diff_sum()

	// ymm0 .. ymm5 = tmp.blend(tmp.diff_sum(), Lanes::AB)
	VPBLENDD LANES_AB, Y5, Y0, Y0
	VPBLENDD LANES_AB, Y6, Y1, Y1
	VPBLENDD LANES_AB, Y7, Y2, Y2
	VPBLENDD LANES_AB, Y8, Y3, Y3
	VPBLENDD LANES_AB, Y9, Y4, Y4

	// out = ymm0 .. ymm4
	store_vec(AX)

	VZEROUPPER
	RET

// func vecAddSubExtendedCached_Step2_AVX2(tmp0, tmp1 *fieldElement2625x4)
TEXT ·vecAddSubExtendedCached_Step2_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ tmp0+0(FP), AX
	MOVQ tmp1+8(FP), BX

	// ymm0 .. ymm4 = tmp0
	load_vec(AX)

	// tmp = tmp.shuffle(Shuffle::ABDC)
	VMOVDQA ·shuffle_ABDC<>(SB), Y15
	VPERMD  Y0, Y15, Y0
	VPERMD  Y1, Y15, Y1
	VPERMD  Y2, Y15, Y2
	VPERMD  Y3, Y15, Y3
	VPERMD  Y4, Y15, Y4

	// ymm5 .. ymm9 = tmp.diff_sum()
	diff_sum()

	VMOVDQA ·shuffle_ADDA<>(SB), Y15
	VMOVDQA ·shuffle_CBCB<>(SB), Y14

	// let t0 = tmp.shuffle(Shuffle::ADDA)
	VPERMD Y5, Y15, Y0
	VPERMD Y6, Y15, Y1
	VPERMD Y7, Y15, Y2
	VPERMD Y8, Y15, Y3
	VPERMD Y9, Y15, Y4

	// let t1 = tmp.shuffle(Shuffle::CBCB)
	VPERMD Y5, Y14, Y5
	VPERMD Y6, Y14, Y6
	VPERMD Y7, Y14, Y7
	VPERMD Y8, Y14, Y8
	VPERMD Y9, Y14, Y9

	// tmp0 = ymm0 .. ymm4
	store_vec(AX)

	// tmp1 = ymm5 .. ymm9
	store_vec_2(BX)

	VZEROUPPER
	RET

// func vecNegateLazyCached_AVX2(out *fieldElement2625x4, vec *cachedPoint)
TEXT ·vecNegateLazyCached_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ out+0(FP), AX
	MOVQ vec+8(FP), BX

	// ymm0 .. ymm4 = vec
	load_vec(BX)

	// ymm0 .. ymm4 = self.0.shuffle(Shuffle::BACD) (swapped)
	VMOVDQA ·shuffle_BACD<>(SB), Y15
	VPERMD  Y0, Y15, Y0
	VPERMD  Y1, Y15, Y1
	VPERMD  Y2, Y15, Y2
	VPERMD  Y3, Y15, Y3
	VPERMD  Y4, Y15, Y4

	// ymm5 .. ymm9 = swapped.negate_lazy()
	VMOVDQA ·p_times_2_lo<>(SB), Y15
	VMOVDQA ·p_times_2_hi<>(SB), Y14
	VPSUBD  Y0, Y15, Y5
	VPSUBD  Y1, Y14, Y6
	VPSUBD  Y2, Y14, Y7
	VPSUBD  Y3, Y14, Y8
	VPSUBD  Y4, Y14, Y9

	// ymm0 .. ymm4 = swapped.blend(swapped.negate_lazy(), Lanes::D)
	VPBLENDD LANES_D, Y5, Y0, Y0
	VPBLENDD LANES_D, Y6, Y1, Y1
	VPBLENDD LANES_D, Y7, Y2, Y2
	VPBLENDD LANES_D, Y8, Y3, Y3
	VPBLENDD LANES_D, Y9, Y4, Y4

	// out = ymm0 .. ymm4
	store_vec(AX)

	VZEROUPPER
	RET

// func vecCachedFromExtended_Step1_AVX2(out *cachedPoint, vec *extendedPoint)
TEXT ·vecCachedFromExtended_Step1_AVX2(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ out+0(FP), AX
	MOVQ vec+8(FP), BX

	// ymm0 .. ymm4 = vec
	load_vec(BX)

	// ymm5 .. ymm9 = x.diff_sum()
	diff_sum()

	// ymm0, ymm4, ymm6, ymm8 = x.blend(x.diff_sum(), Lanes::AB)
	VPBLENDD LANES_AB, Y5, Y0, Y10
	VPBLENDD LANES_AB, Y6, Y1, Y11
	VPBLENDD LANES_AB, Y7, Y2, Y12
	VPBLENDD LANES_AB, Y8, Y3, Y13
	VPBLENDD LANES_AB, Y9, Y4, Y14

	// ymm0 .. ymm9 = x * (121666, 121666, 2 * 121666, 2 * 121665)
	VPXOR Y15, Y15, Y15

	VPUNPCKHDQ Y15, Y10, Y1 // ymm0, ymm1 = unpack_pair(ymm10)
	VPUNPCKLDQ Y15, Y10, Y0
	VPUNPCKHDQ Y15, Y11, Y3 // ymm2, ymm3 = unpack_pair(ymm11)
	VPUNPCKLDQ Y15, Y11, Y2
	VPUNPCKHDQ Y15, Y12, Y5 // ymm4, ymm5 = unpack_pair(ymm12)
	VPUNPCKLDQ Y15, Y12, Y4
	VPUNPCKHDQ Y15, Y13, Y7 // ymm6, ymm7 = unpack_pair(ymm13)
	VPUNPCKLDQ Y15, Y13, Y6
	VPUNPCKHDQ Y15, Y14, Y9 // ymm8, ymm9 = unpack_pair(ymm14)
	VPUNPCKLDQ Y15, Y14, Y8

	VMOVDQA  ·to_cached_scalar<>(SB), Y14
	VPMULUDQ Y14, Y0, Y0
	VPMULUDQ Y14, Y1, Y1
	VPMULUDQ Y14, Y2, Y2
	VPMULUDQ Y14, Y3, Y3
	VPMULUDQ Y14, Y4, Y4
	VPMULUDQ Y14, Y5, Y5
	VPMULUDQ Y14, Y6, Y6
	VPMULUDQ Y14, Y7, Y7
	VPMULUDQ Y14, Y8, Y8
	VPMULUDQ Y14, Y9, Y9

	reduce64()

	VZEROUPPER
	RET

