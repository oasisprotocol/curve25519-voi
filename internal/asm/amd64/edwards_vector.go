// Copyright (c) 2016-2019 isis agora lovecruft. All rights reserved.
// Copyright (c) 2016-2019 Henry de Valence. All rights reserved.
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

//go:build ignore

package main

import (
	"fmt"
	"os"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// This started out as curve25519-dalek's intrinsic based AVX2 backend,
// that was first converted to Go's assembly dialect, and then rewritten
// to use avo for readability.
//
// This could probably use more helpers and what not, but it is still
// a vast improvement over the gigantic wall of insanity that was the
// hand-written version.

const alignPadSize = 64

type shuffleControl int

const (
	SHUFFLE_AAAA shuffleControl = iota
	SHUFFLE_ABDC
	SHUFFLE_ADDA
	SHUFFLE_BACD
	SHUFFLE_BBBB
	SHUFFLE_CACA
	SHUFFLE_CBCB
	SHUFFLE_DBBD

	SHUFFLE_ABAB
	SHUFFLE_BADC
)

var (
	reduce_shifts = newU32x8("reduce_shifts", [8]uint32{
		26, 26, 25, 25, 26, 26, 25, 25,
	})
	reduce_masks = newU32x8("reduce_masks", [8]uint32{
		(1 << 26) - 1, (1 << 26) - 1, (1 << 25) - 1, (1 << 25) - 1,
		(1 << 26) - 1, (1 << 26) - 1, (1 << 25) - 1, (1 << 25) - 1,
	})

	v19 = newU64x4("v19", [4]uint64{
		19, 19, 19, 19,
	})

	p_times_16_lo = newU32x8("p_times_16_lo", [8]uint32{
		67108845 << 4, 67108845 << 4, 33554431 << 4, 33554431 << 4,
		67108845 << 4, 67108845 << 4, 33554431 << 4, 33554431 << 4,
	})
	p_times_16_hi = newU32x8("p_times_16_hi", [8]uint32{
		67108863 << 4, 67108863 << 4, 33554431 << 4, 33554431 << 4,
		67108863 << 4, 67108863 << 4, 33554431 << 4, 33554431 << 4,
	})

	p_times_2_lo = newU32x8("p_times_2_lo", [8]uint32{
		67108845 << 1, 67108845 << 1, 33554431 << 1, 33554431 << 1,
		67108845 << 1, 67108845 << 1, 33554431 << 1, 33554431 << 1,
	})
	p_times_2_hi = newU32x8("p_times_2_hi", [8]uint32{
		67108863 << 1, 67108863 << 1, 33554431 << 1, 33554431 << 1,
		67108863 << 1, 67108863 << 1, 33554431 << 1, 33554431 << 1,
	})

	low_25_bit_mask = newU64x4("low_25_bit_mask", [4]uint64{
		(1 << 25) - 1, (1 << 25) - 1, (1 << 25) - 1, (1 << 25) - 1,
	})
	low_26_bit_mask = newU64x4("low_26_bit_mask", [4]uint64{
		(1 << 26) - 1, (1 << 26) - 1, (1 << 26) - 1, (1 << 26) - 1,
	})

	to_cached_scalar = newU32x8("to_cached_scalar", [8]uint32{
		121666, 0, 121666, 0, 2 * 121666, 0, 2 * 121665, 0,
	})

	low_p_37 = newU64x4("low_p_37", [4]uint64{
		0x3ffffed << 37, 0x3ffffed << 37, 0x3ffffed << 37, 0x3ffffed << 37,
	})
	even_p_37 = newU64x4("even_p_37", [4]uint64{
		0x3ffffff << 37, 0x3ffffff << 37, 0x3ffffff << 37, 0x3ffffff << 37,
	})
	odd_p_37 = newU64x4("odd_p_37", [4]uint64{
		0x1ffffff << 37, 0x1ffffff << 37, 0x1ffffff << 37, 0x1ffffff << 37,
	})

	// VPERMD constants.
	shuffle_AAAA = newU32x8("shuffle_AAAA", [8]uint32{
		0, 0, 2, 2, 0, 0, 2, 2,
	})
	shuffle_ABDC = newU32x8("shuffle_ABDC", [8]uint32{
		0, 1, 2, 3, 5, 4, 7, 6,
	})
	shuffle_ADDA = newU32x8("shuffle_ADDA", [8]uint32{
		0, 5, 2, 7, 5, 0, 7, 2,
	})
	shuffle_BACD = newU32x8("shuffle_BACD", [8]uint32{
		1, 0, 3, 2, 4, 5, 6, 7,
	})
	shuffle_BBBB = newU32x8("shuffle_BBBB", [8]uint32{
		1, 1, 3, 3, 1, 1, 3, 3,
	})
	shuffle_CACA = newU32x8("shuffle_CACA", [8]uint32{
		4, 0, 6, 2, 4, 0, 6, 2,
	})
	shuffle_CBCB = newU32x8("shuffle_CBCB", [8]uint32{
		4, 1, 6, 3, 4, 1, 6, 3,
	})
	shuffle_DBBD = newU32x8("shuffle_DBDB", [8]uint32{
		5, 1, 7, 3, 1, 5, 3, 7,
	})

	// VPBLENDD constants.
	LANES_A   = MM_SHUFFLE(0, 0, 1, 1)
	LANES_B   = MM_SHUFFLE(0, 0, 2, 2)
	LANES_C   = MM_SHUFFLE(1, 1, 0, 0)
	LANES_D   = MM_SHUFFLE(2, 2, 0, 0)
	LANES_D64 = MM_SHUFFLE(3, 0, 0, 0)
	LANES_AB  = LANES_A.(U8) | LANES_B.(U8)
	LANES_AC  = LANES_A.(U8) | LANES_C.(U8)
	LANES_AD  = LANES_A.(U8) | LANES_D.(U8)
	LANES_BC  = LANES_B.(U8) | LANES_C.(U8)
)

func main() {
	for i, step := range []func() error{
		SetCommon,
		VecConditionalSelect,
		VecReduce,
		VecNegate,
		VecAddSubExtendedCached_Step1,
		VecAddSubExtendedCached_Step2,
		VecNegateLazyCached,
		VecConditionalNegateLazyCached,
		VecCachedFromExtended_Step1,
		VecDoubleExtended_Step1,
		VecDoubleExtended_Step2,
		VecMul,
		VecSquareAndNegateD,
	} {
		if err := step(); err != nil {
			fmt.Printf("step %d failed: %v", i, err)
			os.Exit(1)
		}
	}

	Generate()
}

// vecPoint is a point expressed as vectors of 32-bit coefficients.
type vecPoint [5]VecVirtual

func (vec *vecPoint) Allocate() {
	for i := range vec {
		if vec[i] == nil {
			vec[i] = YMM()
		}
	}
}

func (vec *vecPoint) Load(base Mem) {
	vec.Allocate()

	for i, ymm := range vec {
		VMOVDQU(base.Offset(i*32), ymm)
	}
}

func (vec *vecPoint) Store(base Mem) {
	for i, ymm := range vec {
		VMOVDQU(ymm, base.Offset(i*32))
	}
}

func (vec *vecPoint) Shuffle(ctrl shuffleControl) vecPoint {
	out := NewVecPoint()

	// Handle special cases that don't need to use VPERMD.
	switch ctrl {
	case SHUFFLE_ABAB:
		for i := range vec {
			VPERMQ(MM_SHUFFLE(1, 0, 1, 0), vec[i], out[i])
		}
		return out
	case SHUFFLE_BADC:
		for i := range vec {
			VPSHUFD(MM_SHUFFLE(2, 3, 0, 1), vec[i], out[i])
		}
		return out
	}

	shuffle := YMM()
	switch ctrl {
	case SHUFFLE_AAAA:
		VMOVDQA(shuffle_AAAA, shuffle)
	case SHUFFLE_ABDC:
		VMOVDQA(shuffle_ABDC, shuffle)
	case SHUFFLE_ADDA:
		VMOVDQA(shuffle_ADDA, shuffle)
	case SHUFFLE_BACD:
		VMOVDQA(shuffle_BACD, shuffle)
	case SHUFFLE_BBBB:
		VMOVDQA(shuffle_BBBB, shuffle)
	case SHUFFLE_CACA:
		VMOVDQA(shuffle_CACA, shuffle)
	case SHUFFLE_CBCB:
		VMOVDQA(shuffle_CBCB, shuffle)
	case SHUFFLE_DBBD:
		VMOVDQA(shuffle_DBBD, shuffle)
	default:
		panic("amd64: invalid shuffle")
	}

	for i := range vec {
		VPERMD(vec[i], shuffle, out[i])
	}

	return out
}

// Reduce reduces the vector of field elements `mod p`, and writes the results
// to memory.
func (vec *vecPoint) Reduce(base Mem) {
	Comment("Reduce")
	shiftsReg, masksReg := YMM(), YMM()
	VMOVDQA(reduce_shifts, shiftsReg)
	VMOVDQA(reduce_masks, masksReg)

	Comment("c10, .., c98 = rotated_carryout(v[0]), .., rotated_carryout(v[4])")
	cVec := NewVecPoint()
	for i := range vec {
		VPSRLVD(shiftsReg, vec[i], cVec[i])
	}
	for _, ymm := range cVec {
		VPSHUFD(MM_SHUFFLE(1, 0, 3, 2), ymm, ymm)
	}
	c10, c32, c54, c76, c98 := cVec[0], cVec[1], cVec[2], cVec[3], cVec[4]

	Comment("vec &= masks")
	for _, ymm := range vec {
		VPAND(masksReg, ymm, ymm)
	}

	Comment("Combine (lo, .., lo) with (hi, .., hi) to (lo, lo, hi, hi, lo, lo, hi, hi)")
	combinedVec, zero := NewVecPoint(), YMM()
	VPXOR(zero, zero, zero)
	VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), c10, zero, combinedVec[0])
	VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), c32, c10, combinedVec[1])
	VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), c54, c32, combinedVec[2])
	VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), c76, c54, combinedVec[3])
	VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), c98, c76, combinedVec[4])

	Comment("vec += combined")
	for i := range vec {
		VPADDD(vec[i], combinedVec[i], vec[i])
	}

	Comment("vec[0] += c9_19")
	c9_19, c9_spread, c9_19_spread := YMM(), YMM(), YMM()
	VPSHUFD(MM_SHUFFLE(3, 1, 2, 0), c98, c9_spread)
	VPMULUDQ(v19, c9_spread, c9_19_spread)
	VPSHUFD(MM_SHUFFLE(3, 1, 2, 0), c9_19_spread, c9_19)
	VPADDD(vec[0], c9_19, vec[0])

	Comment("Write out the result")
	vec.Store(base)
}

// DiffSum computes `(B - A, B + A, D - C, D + C)`, and returns the result.
func (vec *vecPoint) DiffSum(outputName, inputName string) vecPoint {
	Commentf("tmp1 = %s.shuffle(BADC)", inputName)
	tmp1 := vec.Shuffle(SHUFFLE_BADC)

	Commentf("tmp2 = %s.negate_lazy()", inputName)
	tmp2 := vec.NegateLazy()

	Commentf("tmp2 = %s.blend(tmp2, Lanes::AC)", inputName)
	for i := range tmp2 {
		VPBLENDD(LANES_AC, tmp2[i], vec[i], tmp2[i])
	}

	Commentf("%s = tmp1 + tmp2 (diff_sum result)", outputName)
	for i := range tmp1 {
		VPADDD(tmp1[i], tmp2[i], tmp1[i])
	}

	return tmp1
}

// NegateLazy computes `(-A, -B, -C, -D)` without performing a reduction.
func (vec *vecPoint) NegateLazy() vecPoint {
	lo, hi := YMM(), YMM()
	VMOVDQA(p_times_2_lo, lo)
	VMOVDQA(p_times_2_hi, hi)

	out := NewVecPoint()
	VPSUBD(vec[0], lo, out[0])
	for i := 1; i < len(vec); i++ {
		VPSUBD(vec[i], hi, out[i])
	}

	return out
}

// NegateLazyCached negates a cached point without performing a reduction.
func (vec *vecPoint) NegateLazyCached() vecPoint {
	Comment("swapped = vec.shuffle(Shuffle::BACD)")
	swapped := vec.Shuffle(SHUFFLE_BACD)

	Comment("tmp = swapped.negate_lazy()")
	tmp := swapped.NegateLazy()

	Comment("out = swapped.blend(swapped.NegateLazy(), Lanes::D")
	for i := range tmp {
		VPBLENDD(LANES_D, tmp[i], swapped[i], swapped[i])
	}

	return swapped
}

func LoadVecPoint(base Mem) vecPoint {
	var vec vecPoint
	vec.Load(base)
	return vec
}

func NewVecPoint() vecPoint {
	var vec vecPoint
	vec.Allocate()
	return vec
}

// vecPoint64 is a point expressed as vectors of wide coefficients.
type vecPoint64 [10]VecVirtual

func (vec *vecPoint64) Allocate() {
	for i := range vec {
		if vec[i] == nil {
			vec[i] = YMM()
		}
	}
}

func unpackPair(a, b, fe, zero VecVirtual) {
	// Caller is assumed to have cleared out zero, since this function
	// shouldn't do it each call.
	VPUNPCKHDQ(zero, fe, b)
	VPUNPCKLDQ(zero, fe, a)
}

func (vec *vecPoint64) Load(base Mem) {
	vec.Allocate()

	zero := YMM()
	VPXOR(zero, zero, zero)

	for i := 0; i < 5; i++ {
		idx := i * 2
		a, b := vec[idx], vec[idx+1]
		VMOVDQU(base.Offset(i*32), a)
		unpackPair(a, b, a, zero)
	}
}

func (vec *vecPoint64) Store(base Mem) {
	for i, ymm := range vec {
		VMOVDQU(ymm, base.Offset(i*32))
	}
}

func LoadVecPoint64(base Mem) vecPoint64 {
	var vec vecPoint64
	vec.Load(base)
	return vec
}

func NewVecPoint64() vecPoint64 {
	var vec vecPoint64
	vec.Allocate()
	return vec
}

// Reduce reduces the vector of wide coefficients, and writes the result to memory.
func (vec *vecPoint64) Reduce(base Mem) {
	Comment("Reduce")
	z := vec

	mask25Reg, mask26Reg, v19Reg := YMM(), YMM(), YMM()
	VMOVDQA(low_25_bit_mask, mask25Reg)
	VMOVDQA(low_26_bit_mask, mask26Reg)
	VMOVDQA(v19, v19Reg)

	Comment("Perform two halves of the carry chain in parallel\n")
	parallelCarry := func(a, b int) {
		tmpA, tmpB := YMM(), YMM()

		if a%2 != b%2 {
			panic("amd64: invalid operands for parallel carry")
		}
		var (
			shift Constant
			mask  VecVirtual
		)
		switch a % 2 {
		case 0:
			// Even limbs have 26 bits
			shift, mask = Imm(26), mask26Reg
		case 1:
			// Odd limbs have 25 bits
			shift, mask = Imm(25), mask25Reg
		}
		Comment(fmt.Sprintf("Carry z[%d]/z[%d]", a, b))
		VPSRLQ(shift, z[a], tmpA)
		VPSRLQ(shift, z[b], tmpB)
		VPADDQ(z[a+1], tmpA, z[a+1])
		VPADDQ(z[b+1], tmpB, z[b+1])
		VPAND(mask, z[a], z[a])
		VPAND(mask, z[b], z[b])
	}
	parallelCarry(0, 4)
	parallelCarry(1, 5)
	parallelCarry(2, 6)
	parallelCarry(3, 7)
	parallelCarry(4, 8)

	Comment("Do the final carry")
	c, c0, c1 := YMM(), YMM(), YMM()
	VPSRLQ(Imm(25), z[9], c)
	VPAND(mask25Reg, z[9], z[9])
	VPAND(mask26Reg, c, c0)
	VPSRLQ(Imm(26), c, c1)

	VPMULUDQ(v19Reg, c0, c0)
	VPMULUDQ(v19Reg, c1, c1)

	VPADDQ(z[0], c0, z[0])
	VPADDQ(z[1], c1, z[1])

	// Note: This is equvalent to half of parallelCarry
	tmp := YMM()
	VPSRLQ(Imm(26), z[0], tmp)
	VPADDQ(z[1], tmp, z[1])
	VPAND(mask26Reg, z[0], z[0])

	Comment("Repack 64-bit lanes into 32-bit lanes")
	repackPair := func(a, b int) {
		VPSHUFD(MM_SHUFFLE(3, 1, 2, 0), z[a], z[a])
		VPSHUFD(MM_SHUFFLE(2, 0, 3, 1), z[b], z[b])
		VPBLENDD(MM_SHUFFLE(3, 0, 3, 0), z[b], z[a], z[a])
	}
	repackPair(0, 1)
	repackPair(2, 3)
	repackPair(4, 5)
	repackPair(6, 7)
	repackPair(8, 9)

	Comment("Write out the result")
	outVec := vecPoint{z[0], z[2], z[4], z[6], z[8]}
	outVec.Store(base)
}

// NegateD negates the D value, reduces, and writes the result to memory.
func (vec *vecPoint64) NegateD(base Mem) {
	Comment("Negate D\n")
	z := vec

	Comment("Negate even D values")
	lo, even := YMM(), YMM()
	VMOVDQA(low_p_37, lo)
	VMOVDQA(even_p_37, even)

	t0, t2, t4, t6, t8 := YMM(), YMM(), YMM(), YMM(), YMM()
	VPSUBQ(z[0], lo, t0)
	VPSUBQ(z[2], even, t2)
	VPSUBQ(z[4], even, t4)
	VPSUBQ(z[6], even, t6)
	VPSUBQ(z[8], even, t8)

	VPBLENDD(LANES_D64, t0, z[0], z[0])
	VPBLENDD(LANES_D64, t2, z[2], z[2])
	VPBLENDD(LANES_D64, t4, z[4], z[4])
	VPBLENDD(LANES_D64, t6, z[6], z[6])
	VPBLENDD(LANES_D64, t8, z[8], z[8])

	Comment("Negate odd D values")
	odd := YMM()
	VMOVDQA(odd_p_37, odd)

	t1, t3, t5, t7, t9 := YMM(), YMM(), YMM(), YMM(), YMM()
	VPSUBQ(z[1], odd, t1)
	VPSUBQ(z[3], odd, t3)
	VPSUBQ(z[5], odd, t5)
	VPSUBQ(z[7], odd, t7)
	VPSUBQ(z[9], odd, t9)

	VPBLENDD(LANES_D64, t1, z[1], z[1])
	VPBLENDD(LANES_D64, t3, z[3], z[3])
	VPBLENDD(LANES_D64, t5, z[5], z[5])
	VPBLENDD(LANES_D64, t7, z[7], z[7])
	VPBLENDD(LANES_D64, t9, z[9], z[9])

	vec.Reduce(base)
}

func VecConditionalSelect() error {
	TEXT(
		"vecConditionalSelect_AVX2",
		NOSPLIT|NOFRAME,
		"func(out, a, b *fieldElement2625x4, mask uint32)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	aMem := Mem{Base: Load(Param("a"), GP64())}
	bMem := Mem{Base: Load(Param("b"), GP64())}
	mask := NewParamAddr("mask", 24)

	Comment("maskVec = [mask, .., mask]")
	maskVec := YMM()
	VPBROADCASTD(mask, maskVec)

	Comment("b = b & maskVec")
	b := NewVecPoint()
	for i := range b {
		VPAND(bMem.Offset(i*32), maskVec, b[i])
	}

	Comment("tmp = (!a) & maskVec")
	tmp := NewVecPoint()
	for i := range tmp {
		VPANDN(aMem.Offset(i*32), maskVec, tmp[i])
	}

	Comment("b |= tmp")
	for i := range b {
		VPOR(b[i], tmp[i], b[i])
	}

	Comment("Store output")
	b.Store(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecReduce() error {
	TEXT(
		"vecReduce_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}

	Comment("Load out")
	outVec := LoadVecPoint(out)

	outVec.Reduce(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecNegate() error {
	TEXT(
		"vecNegate_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}

	lo, hi := YMM(), YMM()
	VMOVDQA(p_times_16_lo, lo)
	VMOVDQA(p_times_16_hi, hi)

	Comment("out = p * 16 - out")
	outVec := NewVecPoint()
	VPSUBD(out.Offset(0), lo, outVec[0])
	for i := 1; i < len(outVec); i++ {
		VPSUBD(out.Offset(32*i), hi, outVec[i])
	}

	outVec.Reduce(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecAddSubExtendedCached_Step1() error {
	TEXT(
		"vecAddSubExtendedCached_Step1_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4, vec *extendedPoint)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	vec := LoadVecPoint(Mem{Base: Load(Param("vec"), GP64())})

	Comment("tmp = vec.diff_sum()\n")
	tmp := vec.DiffSum("tmp", "vec")

	Comment("out = vec.blend(tmp, Lanes::AB)")
	for i := range tmp {
		VPBLENDD(LANES_AB, tmp[i], vec[i], vec[i])
	}

	Comment("Write out the result")
	vec.Store(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecAddSubExtendedCached_Step2() error {
	TEXT(
		"vecAddSubExtendedCached_Step2_AVX2",
		NOSPLIT|NOFRAME,
		"func(tmp0, tmp1 *fieldElement2625x4)",
	)

	tmp0 := Mem{Base: Load(Param("tmp0"), GP64())}
	tmp1 := Mem{Base: Load(Param("tmp1"), GP64())}

	tmp := LoadVecPoint(tmp0)

	Comment("tmp = tmp0.shuffle(Shuffle::ABDC)")
	tmp = tmp.Shuffle(SHUFFLE_ABDC)

	Comment("tmp = tmp.diff_sum()\n")
	tmp = tmp.DiffSum("tmp", "tmp")

	Comment("t0 = tmp.shuffle(Shuffle::ADDA)")
	t0 := tmp.Shuffle(SHUFFLE_ADDA)

	Comment("t1 = tmp.shuffle(Shuffle::CBCB")
	t1 := tmp.Shuffle(SHUFFLE_CBCB)

	Comment("Write out t0")
	t0.Store(tmp0)

	Comment("Write out t1")
	t1.Store(tmp1)

	VZEROUPPER()
	RET()

	return nil
}

func VecNegateLazyCached() error {
	TEXT(
		"vecNegateLazyCached_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4, vec *cachedPoint)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	vec := LoadVecPoint(Mem{Base: Load(Param("vec"), GP64())})

	swapped := vec.NegateLazyCached()

	Comment("Write out the result")
	swapped.Store(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecConditionalNegateLazyCached() error {
	TEXT(
		"vecConditionalNegateLazyCached_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4, vec *cachedPoint, mask uint32)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	vec := LoadVecPoint(Mem{Base: Load(Param("vec"), GP64())})

	swapped := vec.NegateLazyCached()

	Comment("ConditionalSelect(a = vec, b = -vec, mask)")
	tmp, b := vec, swapped

	Comment("maskVec = [mask, .., mask]")
	mask := NewParamAddr("mask", 16)
	maskVec := YMM()
	VPBROADCASTD(mask, maskVec)

	Comment("b = b & maskVec")
	for i := range b {
		VPAND(b[i], maskVec, b[i])
	}

	Comment("tmp = (!a) & maskVec")
	for i := range tmp {
		VPANDN(tmp[i], maskVec, tmp[i])
	}

	Comment("b |= tmp")
	for i := range b {
		VPOR(b[i], tmp[i], b[i])
	}

	Comment("Store output")
	b.Store(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecCachedFromExtended_Step1() error {
	TEXT(
		"vecCachedFromExtended_Step1_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *cachedPoint, vec *extendedPoint)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	x := LoadVecPoint(Mem{Base: Load(Param("vec"), GP64())})

	Comment("x = vec\n")

	Comment("tmp = x.diff_sum()\n")
	tmp := x.DiffSum("tmp", "x")

	Comment("x = x.blend(tmp, LANES::AB)")
	for i := range tmp {
		VPBLENDD(LANES_AB, tmp[i], x[i], x[i])
	}

	Comment("x = x * (121666, 121666, 2 * 121666, 2 * 121665)\n")

	Comment("Unpack x")
	zero := YMM()
	VPXOR(zero, zero, zero)

	wide := NewVecPoint64()
	unpackPair(wide[0], wide[1], x[0], zero)
	unpackPair(wide[2], wide[3], x[1], zero)
	unpackPair(wide[4], wide[5], x[2], zero)
	unpackPair(wide[6], wide[7], x[3], zero)
	unpackPair(wide[8], wide[9], x[4], zero)

	Comment("Multiply x by the constant")
	multiplier := YMM()
	VMOVDQA(to_cached_scalar, multiplier)
	for _, ymm := range wide {
		VPMULUDQ(multiplier, ymm, ymm)
	}

	wide.Reduce(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecDoubleExtended_Step1() error {
	TEXT(
		"vecDoubleExtended_Step1_AVX2",
		NOSPLIT|NOFRAME,
		"func(out *fieldElement2625x4, vec *extendedPoint)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}
	vec := LoadVecPoint(Mem{Base: Load(Param("vec"), GP64())})

	Comment("tmp0 = vec.shuffle(Shuffle::ABAB) (tmp0 = (X1 Y1 X1 Y1)")
	tmp0 := vec.Shuffle(SHUFFLE_ABAB)

	Comment("tmp1 = tmp0.shuffle(Shuffle::BADC) (tmp1 = (Y1 X1 Y1 X1)")
	tmp1 := tmp0.Shuffle(SHUFFLE_BADC)

	Comment("tmp = tmp0 + tmp1")
	tmp := NewVecPoint()
	for i, ymm := range tmp {
		VPADDD(tmp0[i], tmp1[i], ymm)
	}

	Comment("tmp0 = vec.blend(tmp, Lanes::D)")
	for i := range vec {
		VPBLENDD(LANES_D, tmp[i], vec[i], tmp0[i])
	}

	Comment("Write out the result")
	tmp0.Store(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecDoubleExtended_Step2() error {
	TEXT(
		"vecDoubleExtended_Step2_AVX2",
		NOSPLIT|NOFRAME,
		"func(tmp0, tmp1 *fieldElement2625x4)",
	)

	tmp0Mem := Mem{Base: Load(Param("tmp0"), GP64())}
	tmp1Mem := Mem{Base: Load(Param("tmp1"), GP64())}

	zero := YMM()
	VPXOR(zero, zero, zero)

	// Note: Reordered from the dalek version, due to register pressure.
	tmp1 := LoadVecPoint(tmp1Mem)

	Comment("tmp = tmp1 + tmp1")
	tmp := NewVecPoint()
	for i := range tmp {
		VPADDD(tmp1[i], tmp1[i], tmp[i])
	}

	Comment("tmp0 = zero.blend(tmp, Lanes::C)")
	tmp0 := NewVecPoint()
	for i := range tmp0 {
		VPBLENDD(LANES_C, tmp[i], zero, tmp0[i])
	}

	Comment("tmp0 = tmp0.blend(tmp1, Lanes::D)")
	for i := range tmp0 {
		VPBLENDD(LANES_D, tmp1[i], tmp0[i], tmp0[i])
	}

	Comment("S_1 = tmp1.shuffle(Shuffle::AAAA)")
	S_1 := tmp1.Shuffle(SHUFFLE_AAAA)

	Comment("tmp0 = tmp0 + S_1")
	for i := range tmp0 {
		VPADDD(tmp0[i], S_1[i], tmp0[i])
	}

	Comment("S_2 = tmp1.shuffle(Shuffle::BBBB)")
	S_2 := tmp1.Shuffle(SHUFFLE_BBBB)

	Comment("tmp = zero.blend(S_2, Lanes::AD)")
	for i := range tmp {
		VPBLENDD(LANES_AD, S_2[i], zero, tmp[i])
	}

	Comment("tmp0 = tmp0 + tmp")
	for i := range tmp0 {
		VPADDD(tmp0[i], tmp[i], tmp0[i])
	}

	Comment("tmp = S_2.negate_lazy()")
	tmp = S_2.NegateLazy()

	Comment("tmp = zero.blend(tmp, Lanes::BC)")
	for i := range tmp {
		VPBLENDD(LANES_BC, tmp[i], zero, tmp[i])
	}

	Comment("tmp0 = tmp0 + tmp")
	for i := range tmp0 {
		VPADDD(tmp0[i], tmp[i], tmp0[i])
	}

	Comment("tmp1 = tmp0.shuffle(Shuffle::DBBD)")
	tmp1 = tmp0.Shuffle(SHUFFLE_DBBD)

	Comment("tmp0 = tmp0.shuffle(Shuffle::CACA)")
	tmp0 = tmp0.Shuffle(SHUFFLE_CACA)

	Comment("Write out tmp0")
	tmp0.Store(tmp0Mem)

	Comment("Write out tmp1")
	tmp1.Store(tmp1Mem)

	VZEROUPPER()
	RET()

	return nil
}

func VecMul() error {
	TEXT(
		"vecMul_AVX2",
		0,
		"func(out, a, b *fieldElement2625x4)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}

	Comment("Align the stack on a 64 byte boundary (cache line aligned)")
	const (
		zSpillSize   = 5 * 32  // Even z vectors
		vecSpillSize = 10 * 32 // x/y
		y19SpillSize = 3 * 32  // Y2_19, Y3_19, Y4_19
	)
	AllocLocal(alignPadSize + zSpillSize + vecSpillSize + vecSpillSize + y19SpillSize)
	stackReg := GP64()
	MOVQ(RSP, stackReg)
	ADDQ(Imm(64), stackReg)
	ANDQ(U32(0xffffffc0), stackReg)

	alignedStack := Mem{Base: stackReg}
	zSpill := alignedStack.Offset(0)
	xSpill := zSpill.Offset(zSpillSize)
	ySpill := xSpill.Offset(vecSpillSize)
	y19Spill := ySpill.Offset(vecSpillSize)

	x := func(idx int) Mem {
		return xSpill.Offset(idx * 32)
	}
	y := func(idx int) Mem {
		return ySpill.Offset(idx * 32)
	}
	z := func(idx int) Mem {
		// Index is by vector slot, not spill slot for readablility.
		return zSpill.Offset(idx / 2 * 32)
	}
	Y2_19 := y19Spill.Offset(0)
	Y3_19 := y19Spill.Offset(32)
	Y4_19 := y19Spill.Offset(64)

	Comment("Load, unpack, and spill a (x)")
	aTmp := LoadVecPoint64(Mem{Base: Load(Param("a"), GP64())})
	aTmp.Store(xSpill)

	Comment("Load, unpack, and spill b (y)")
	bTmp := LoadVecPoint64(Mem{Base: Load(Param("b"), GP64())})
	bTmp.Store(ySpill)

	Comment("Precompute (y1 .. y9) * 19")
	v19Reg, Y5_19, Y6_19, Y7_19, Y8_19, Y9_19 := YMM(), YMM(), YMM(), YMM(), YMM(), YMM()
	VMOVDQA(v19, v19Reg)
	VPMULUDQ(bTmp[1], v19Reg, bTmp[1]) // y1 * 19
	VPMULUDQ(bTmp[2], v19Reg, bTmp[2]) // y2 * 18
	VPMULUDQ(bTmp[3], v19Reg, bTmp[3]) // y3 * 19
	VPMULUDQ(bTmp[4], v19Reg, bTmp[4]) // y4 * 19
	VPMULUDQ(bTmp[5], v19Reg, Y5_19)   // y5 * 19
	VPMULUDQ(bTmp[6], v19Reg, Y6_19)   // y6 * 19
	VPMULUDQ(bTmp[7], v19Reg, Y7_19)   // y7 * 19
	VPMULUDQ(bTmp[8], v19Reg, Y8_19)   // y8 * 19
	VPMULUDQ(bTmp[9], v19Reg, Y9_19)   // y9 * 19
	VMOVDQA(bTmp[2], Y2_19)
	VMOVDQA(bTmp[3], Y3_19)
	VMOVDQA(bTmp[4], Y4_19)

	Comment("Handle even z vectors\n")
	// We already have a bunch of registers allocated.
	//
	// Note: T0 and T2 contain y1 * 19, and y3 * 19, which are used
	// immediately, despite the latter also being spilled.
	Z0, Z2, Z4, Z6, Z8 := bTmp[0], bTmp[2], bTmp[4], bTmp[6], bTmp[8]
	T0, T2, T4, T6, T8 := bTmp[1], bTmp[3], bTmp[5], bTmp[7], bTmp[9]
	addEvens := func() {
		VPADDQ(Z0, T0, Z0)
		VPADDQ(Z2, T2, Z2)
		VPADDQ(Z4, T4, Z4)
		VPADDQ(Z6, T6, Z6)
		VPADDQ(Z8, T8, Z8)
	}

	Comment(
		"z0 = m(x9_2,y1_19)",
		"z2 = m(x9_2,y3_19)",
		"z4 = m(x9_2,y5_19)",
		"z6 = m(x9_2,y7_19)",
		"z8 = m(x9_2,y9_19)",
	)
	X9_2 := YMM()
	VMOVDQA(x(9), X9_2)
	VPADDD(X9_2, X9_2, X9_2)
	VPMULUDQ(T0, X9_2, Z0)    // z0 = m(x9_2,y1_19)
	VPMULUDQ(T2, X9_2, Z2)    // z2 = m(x9_2,y3_19)
	VPMULUDQ(Y5_19, X9_2, Z4) // z4 = m(x9_2,y5_19)
	VPMULUDQ(Y7_19, X9_2, Z6) // z6 = m(x9_2,y7_19)
	VPMULUDQ(Y9_19, X9_2, Z8) // z8 = m(x9_2,y9_19)
	X9_2 = nil

	Comment(
		"z0 += m(x8,y2_19)",
		"z2 += m(x8,y4_19)",
		"z4 += m(x8,y6_19)",
		"z6 += m(x8,y8_19)",
		"z8 += m(x8,y0)",
	)
	X8 := YMM()
	VMOVDQA(x(8), X8)
	VPMULUDQ(Y2_19, X8, T0) // t0 = m(x8,y2_19)
	VPMULUDQ(Y4_19, X8, T2) // t2 = m(x8,y4_19)
	VPMULUDQ(Y6_19, X8, T4) // t4 = m(x8,y6_19)
	VPMULUDQ(Y8_19, X8, T6) // t6 = m(x8,y8_19)
	VPMULUDQ(y(0), X8, T8)  // t8 = m(x8,y0)
	addEvens()              // z += t
	X8 = nil

	Comment(
		"z0 += m(x7_2,y3_19)",
		"z2 += m(x7_2,y5_19)",
		"z4 += m(x7_2,y7_19)",
		"z6 += m(x7_2,y9_19)",
		"z8 += m(x7_2,y1)",
	)
	X7_2 := YMM()
	VMOVDQA(x(7), X7_2)
	VPADDD(X7_2, X7_2, X7_2)
	VPMULUDQ(Y3_19, X7_2, T0) // t0 = m(x7_2,y3_19)
	VPMULUDQ(Y5_19, X7_2, T2) // t2 = m(x7_2,y5_19)
	VPMULUDQ(Y7_19, X7_2, T4) // t4 = m(x7_2,y7_19)
	VPMULUDQ(Y9_19, X7_2, T6) // t6 = m(x7_2,y9_19)
	VPMULUDQ(y(1), X7_2, T8)  // t8 = m(x7_2,y1)
	addEvens()                // z += t
	X7_2 = nil

	Comment(
		"z0 += m(x6,y4_19)",
		"z2 += m(x6,y6_19)",
		"z4 += m(x6,y8_19)",
		"z6 += m(x6,y0)",
		"z8 += m(x6,y2)",
	)
	X6 := YMM()
	VMOVDQA(x(6), X6)
	VPMULUDQ(Y4_19, X6, T0) // t0 = m(x6,y4_19)
	VPMULUDQ(Y6_19, X6, T2) // t2 = m(x6,y6_19)
	VPMULUDQ(Y8_19, X6, T4) // t4 = m(x6,y8_19)
	VPMULUDQ(y(0), X6, T6)  // t6 = m(x6,y0)
	VPMULUDQ(y(2), X6, T8)  // t8 = m(x6,y2)
	addEvens()              // z += t
	X6 = nil

	Comment(
		"z0 += m(x5_2,y5_19)",
		"z2 += m(x5_2,y7_19)",
		"z4 += m(x5_2,y9_19)",
		"z6 += m(x5_2,y1)",
		"z8 += m(x5_2,y3)",
	)
	X5_2 := YMM()
	VMOVDQA(x(5), X5_2)
	VPADDD(X5_2, X5_2, X5_2)
	VPMULUDQ(Y5_19, X5_2, T0) // t0 = m(x5_2,y5_19)
	VPMULUDQ(Y7_19, X5_2, T2) // t2 = m(x5_2,y7_19)
	VPMULUDQ(Y9_19, X5_2, T4) // t4 = m(x5_2,y9_19)
	VPMULUDQ(y(1), X5_2, T6)  // t6 = m(x5_2,y1)
	VPMULUDQ(y(3), X5_2, T8)  // t8 = m(x5_2,y3)
	addEvens()                // z += t
	X5_2 = nil

	Comment(
		"z0 += m(x4,y6_19)",
		"z2 += m(x4,y8_19)",
		"z4 += m(x4,y0)",
		"z6 += m(x4,y2)",
		"z8 += m(x4,y4)",
	)
	X4 := YMM()
	VMOVDQA(x(4), X4)
	VPMULUDQ(Y6_19, X4, T0) // t0 = m(x4,y6_19)
	VPMULUDQ(Y8_19, X4, T2) // t2 = m(x4,y8_19)
	VPMULUDQ(y(0), X4, T4)  // t4 = m(x4,y0)
	VPMULUDQ(y(2), X4, T6)  // t6 = m(x4,y2)
	VPMULUDQ(y(4), X4, T8)  // t8 = m(x4,y4)
	addEvens()              // z += t
	X4 = nil

	Comment(
		"z0 += m(x3_2,y7_19)",
		"z2 += m(x3_2,y9_19)",
		"z4 += m(x3_2,y1)",
		"z6 += m(x3_2,y3)",
		"z8 += m(x3_2,y5)",
	)
	X3_2 := YMM()
	VMOVDQA(x(3), X3_2)
	VPADDD(X3_2, X3_2, X3_2)
	VPMULUDQ(Y7_19, X3_2, T0) // t0 = m(x3_2,y7_19)
	VPMULUDQ(Y9_19, X3_2, T2) // t2 = m(x3_2,y9_19)
	VPMULUDQ(y(1), X3_2, T4)  // t4 = m(x3_2,y1)
	VPMULUDQ(y(3), X3_2, T6)  // t6 = m(x3_2,y3)
	VPMULUDQ(y(5), X3_2, T8)  // t8 = m(x3_2,y5)
	addEvens()                // z += t
	X3_2 = nil

	Comment(
		"z0 += m(x2,y8_19)",
		"z2 += m(x2,y0)",
		"z4 += m(x2,y2)",
		"z6 += m(x2,y4)",
		"z8 += m(x2,y6)",
	)
	X2 := YMM()
	VMOVDQA(x(2), X2)
	VPMULUDQ(Y8_19, X2, T0) // t0 = m(x2,y8_19)
	VPMULUDQ(y(0), X2, T2)  // t2 = m(x2,y0)
	VPMULUDQ(y(2), X2, T4)  // t4 = m(x2,y2)
	VPMULUDQ(y(4), X2, T6)  // t6 = m(x2,y4)
	VPMULUDQ(y(6), X2, T8)  // t8 = m(x2,y6)
	addEvens()              // z += t
	X2 = nil

	Comment(
		"z0 += m(x1_2,y9_19)",
		"z2 += m(x1_2,y1)",
		"z4 += m(x1_2,y3)",
		"z6 += m(x1_2,y5)",
		"z8 += m(x1_2,y7)",
	)
	X1_2 := YMM()
	VMOVDQA(x(1), X1_2)
	VPADDD(X1_2, X1_2, X1_2)
	VPMULUDQ(Y9_19, X1_2, T0) // t0 = m(x1_2,y9_19)
	VPMULUDQ(y(1), X1_2, T2)  // t2 = m(x1_2,y1)
	VPMULUDQ(y(3), X1_2, T4)  // t4 = m(x1_2,y3)
	VPMULUDQ(y(5), X1_2, T6)  // t6 = m(x1_2,y5)
	VPMULUDQ(y(7), X1_2, T8)  // t8 = m(x1_2,y7)
	addEvens()                // z += t
	X1_2 = nil

	Comment(
		"z0 += m(x0,y0)",
		"z2 += m(x0,y2)",
		"z4 += m(x0,y4)",
		"z6 += m(x0,y6)",
		"z8 += m(x0,y8)",
	)
	X0 := YMM()
	VMOVDQA(x(0), X0)
	VPMULUDQ(y(0), X0, T0) // t0 = m(x0,y0)
	VPMULUDQ(y(2), X0, T2) // t2 = m(x0,y2)
	VPMULUDQ(y(4), X0, T4) // t4 = m(x0,y4)
	VPMULUDQ(y(6), X0, T6) // t6 = m(x0,y6)
	VPMULUDQ(y(8), X0, T8) // t8 = m(x0,y8)
	addEvens()             // z += t
	X0 = nil

	Comment("Spill the completed z0, z2, z4, z6, z8 onto the stack")
	VMOVDQA(Z0, z(0))
	VMOVDQA(Z2, z(2))
	VMOVDQA(Z4, z(4))
	VMOVDQA(Z6, z(6))
	VMOVDQA(Z8, z(8))

	Comment("Handle odd z vectors\n")
	Z1, Z3, Z5, Z7, Z9 := T0, T2, T4, T6, T8
	T1, T3, T5, T7, T9 := Z0, Z2, Z4, Z6, Z8
	addOdds := func() {
		VPADDQ(Z1, T1, Z1)
		VPADDQ(Z3, T3, Z3)
		VPADDQ(Z5, T5, Z5)
		VPADDQ(Z7, T7, Z7)
		VPADDQ(Z9, T9, Z9)
	}

	Comment(
		"z1 = m(x9,y2_19)",
		"z3 = m(x9,y4_19)",
		"z5 = m(x9,y6_19)",
		"z7 = m(x9,y8_19)",
		"z9 = m(x9,y0)",
	)
	X9 := YMM()
	VMOVDQA(x(9), X9)
	VPMULUDQ(Y2_19, X9, Z1) // z1 = m(x9,y2_19)
	VPMULUDQ(Y4_19, X9, Z3) // z3 = m(x9,y4_19)
	VPMULUDQ(Y6_19, X9, Z5) // z5 = m(x9,y6_19)
	VPMULUDQ(Y8_19, X9, Z7) // z7 = m(x9,y8_19)
	VPMULUDQ(y(0), X9, Z9)  // z9 = m(x9,y0)
	X9 = nil

	Comment(
		"z1 += m(x8,y3_19)",
		"z3 += m(x8,y5_19)",
		"z5 += m(x8,y7_19)",
		"z7 += m(x8,y9_19)",
		"z9 += m(x8,y1)",
	)
	X8 = YMM()
	VMOVDQA(x(8), X8)
	VPMULUDQ(Y3_19, X8, T1) // t1 = m(x8,y3_19)
	VPMULUDQ(Y5_19, X8, T3) // t3 = m(x8,y5_19)
	VPMULUDQ(Y7_19, X8, T5) // t5 = m(x8,y7_19)
	VPMULUDQ(Y9_19, X8, T7) // t7 = m(x8,y9_19)
	VPMULUDQ(y(1), X8, T9)  // t9 = m(x8,y1)
	addOdds()               // z += t
	X8 = nil

	Comment(
		"z1 += m(x7,y4_19)",
		"z3 += m(x7,y6_19)",
		"z5 += m(x7,y8_19)",
		"z7 += m(x7,y0)",
		"z9 += m(x7,y2)",
	)
	X7 := YMM()
	VMOVDQA(x(7), X7)
	VPMULUDQ(Y4_19, X7, T1) // t1 = m(x7,y4_19)
	VPMULUDQ(Y6_19, X7, T3) // t3 = m(x7,y6_19)
	VPMULUDQ(Y8_19, X7, T5) // t5 = m(x7,y8_19)
	VPMULUDQ(y(0), X7, T7)  // t7 = m(x7,y0)
	VPMULUDQ(y(2), X7, T9)  // t9 = m(x7,y2)
	addOdds()               // z += t
	X7 = nil

	Comment(
		"z1 += m(x6,y5_19)",
		"z3 += m(x6,y7_19)",
		"z5 += m(x6,y9_19)",
		"z7 += m(x6,y1)",
		"z9 += m(x6,y3)",
	)
	X6 = YMM()
	VMOVDQA(x(6), X6)
	VPMULUDQ(Y5_19, X6, T1) // t1 = m(x6,y5_19)
	VPMULUDQ(Y7_19, X6, T3) // t3 = m(x6,y7_19)
	VPMULUDQ(Y9_19, X6, T5) // t5 = m(x6,y9_19)
	VPMULUDQ(y(1), X6, T7)  // t7 = m(x6,y1)
	VPMULUDQ(y(3), X6, T9)  // t9 = m(x6,y3)
	addOdds()               // z += t
	X6 = nil

	Comment(
		"z1 += m(x5,y6_19)",
		"z3 += m(x5,y8_19)",
		"z5 += m(x5,y0)",
		"z7 += m(x5,y2)",
		"z9 += m(x5,y4)",
	)
	X5 := YMM()
	VMOVDQA(x(5), X5)
	VPMULUDQ(Y6_19, X5, T1) // t1 = m(x5,y6_19)
	VPMULUDQ(Y8_19, X5, T3) // t3 = m(x5,y8_19)
	VPMULUDQ(y(0), X5, T5)  // t5 = m(x5,y0)
	VPMULUDQ(y(2), X5, T7)  // t7 = m(x5,y2)
	VPMULUDQ(y(4), X5, T9)  // t9 = m(x5,y4)
	addOdds()               // z += t
	X5 = nil

	Comment(
		"z1 += m(x4,y7_19)",
		"z3 += m(x4,y9_19)",
		"z5 += m(x4,y1)",
		"z7 += m(x4,y3)",
		"z9 += m(x4,y5)",
	)
	X4 = YMM()
	VMOVDQA(x(4), X4)
	VPMULUDQ(Y7_19, X4, T1) // t1 = m(x4,y7_19)
	VPMULUDQ(Y9_19, X4, T3) // t3 = m(x4,y9_19)
	VPMULUDQ(y(1), X4, T5)  // t5 = m(x4,y1)
	VPMULUDQ(y(3), X4, T7)  // t7 = m(x4,y3)
	VPMULUDQ(y(5), X4, T9)  // t9 = m(x4,y5)
	addOdds()               // z += t
	X4 = nil

	Comment(
		"z1 += m(x3,y8_19)",
		"z3 += m(x3,y0)",
		"z5 += m(x3,y2)",
		"z7 += m(x3,y4)",
		"z9 += m(x3,y6)",
	)
	X3 := YMM()
	VMOVDQA(x(3), X3)
	VPMULUDQ(Y8_19, X3, T1) // t1 = m(x3,y8_19)
	VPMULUDQ(y(0), X3, T3)  // t3 = m(x3,y0)
	VPMULUDQ(y(2), X3, T5)  // t5 = m(x3,y2)
	VPMULUDQ(y(4), X3, T7)  // t7 = m(x3,y4)
	VPMULUDQ(y(6), X3, T9)  // t9 = m(x3,y6)
	addOdds()               // z += t
	X3 = nil

	Comment(
		"z1 += m(x2,y9_19)",
		"z3 += m(x2,y1)",
		"z5 += m(x2,y3)",
		"z7 += m(x2,y5)",
		"z9 += m(x2,y7)",
	)
	X2 = YMM()
	VMOVDQA(x(2), X2)
	VPMULUDQ(Y9_19, X2, T1) // t1 = m(x2,y9_19)
	VPMULUDQ(y(1), X2, T3)  // t3 = m(x2,y1)
	VPMULUDQ(y(3), X2, T5)  // t5 = m(x2,y3)
	VPMULUDQ(y(5), X2, T7)  // t7 = m(x2,y5)
	VPMULUDQ(y(7), X2, T9)  // t9 = m(x2,y7)
	addOdds()               // z += t
	X2 = nil

	Comment(
		"z1 += m(x1,y0)",
		"z3 += m(x1,y2)",
		"z5 += m(x1,y4)",
		"z7 += m(x1,y6)",
		"z9 += m(x1,y8)",
	)
	X1 := YMM()
	VMOVDQA(x(1), X1)
	VPMULUDQ(y(0), X1, T1) // t1 = m(x1,y0)
	VPMULUDQ(y(2), X1, T3) // t3 = m(x1,y2)
	VPMULUDQ(y(4), X1, T5) // t5 = m(x1,y4)
	VPMULUDQ(y(6), X1, T7) // t7 = m(x1,y6)
	VPMULUDQ(y(8), X1, T9) // t9 = m(x1,y8)
	addOdds()              // z += t
	X1 = nil

	Comment(
		"z1 += m(x0,y1)",
		"z3 += m(x0,y3)",
		"z5 += m(x0,y5)",
		"z7 += m(x0,y7)",
		"z9 += m(x0,y9)",
	)
	X0 = YMM()
	VMOVDQA(x(0), X0)
	VPMULUDQ(y(1), X0, T1) // t1 = m(x0,y1)
	VPMULUDQ(y(3), X0, T3) // t3 = m(x0,y3)
	VPMULUDQ(y(5), X0, T5) // t5 = m(x0,y5)
	VPMULUDQ(y(7), X0, T7) // t7 = m(x0,y7)
	VPMULUDQ(y(9), X0, T9) // t9 = m(x0,y9)
	addOdds()              // z += t
	X0 = nil

	Comment("Restore the completed z0, z2, z4, z6, z8 from the stack")
	VMOVDQA(z(0), Z0)
	VMOVDQA(z(2), Z2)
	VMOVDQA(z(4), Z4)
	VMOVDQA(z(6), Z6)
	VMOVDQA(z(8), Z8)

	toReduce := vecPoint64{Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9}
	toReduce.Reduce(out)

	VZEROUPPER()
	RET()

	return nil
}

func VecSquareAndNegateD() error {
	TEXT(
		"vecSquareAndNegateD_AVX2",
		0,
		"func(out *fieldElement2625x4)",
	)

	out := Mem{Base: Load(Param("out"), GP64())}

	Comment("Align the stack on a 64 byte boundary (cache line aligned)")
	const (
		tmpSpillSize = 5 * 32
		vecSpillSize = 10 * 32 // x
	)
	AllocLocal(alignPadSize + tmpSpillSize + vecSpillSize)
	stackReg := GP64()
	MOVQ(RSP, stackReg)
	ADDQ(Imm(64), stackReg)
	ANDQ(U32(0xffffffc0), stackReg)

	alignedStack := Mem{Base: stackReg}
	tmpSpill := alignedStack.Offset(0)
	xSpill := tmpSpill.Offset(tmpSpillSize)

	x := func(idx int) Mem {
		return xSpill.Offset(idx * 32)
	}
	tmp := func(idx int) Mem {
		return tmpSpill.Offset(idx * 32)
	}

	Comment("Load, unpack, and spill out (x)")
	outTmp := LoadVecPoint64(out)
	outTmp.Store(xSpill)

	Comment("Precompute (x1, x3, x5, x7) * 2")
	v19Reg, X1_2, X3_2, X5_2, X7_2 := YMM(), YMM(), YMM(), YMM(), YMM()
	VMOVDQA(v19, v19Reg)
	VPADDD(outTmp[1], outTmp[1], X1_2) // x1 * 2
	VPADDD(outTmp[3], outTmp[3], X3_2) // x3 * 2
	VPADDD(outTmp[5], outTmp[5], X5_2) // x5 * 2
	VPADDD(outTmp[7], outTmp[7], X7_2) // x7 * 2

	Comment(
		"z0 = m(x1_2,x9_19)",
		"z1 = m(x2,x9_19)",
		"z2 = m(x3_2,x9_19)",
		"z3 = m(x4,x9_19)",
		"z4 = m(x5_2,x9_19)",
		"z5 = m(x6,x9_19)",
		"z6 = m(x7_2,x9_19)",
		"z7 = m(x8,x9_19)",
		"z8 = m(x9,x9_19)",
	)
	Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8 := outTmp[0], outTmp[1], outTmp[2], outTmp[3], outTmp[4], outTmp[5], outTmp[6], outTmp[7], outTmp[8]
	X9_19 := YMM()
	VPMULUDQ(v19Reg, outTmp[9], X9_19)
	VPMULUDQ(X1_2, X9_19, Z0)      // z0 = m(x1_2,x9_19)
	VPMULUDQ(outTmp[2], X9_19, Z1) // z1 = m(x2,x9_19)
	VPMULUDQ(X3_2, X9_19, Z2)      // z2 = m(x3_2,x9_19)
	VPMULUDQ(outTmp[4], X9_19, Z3) // z3 = m(x4,x9_19)
	VPMULUDQ(X5_2, X9_19, Z4)      // z4 = m(x5_2,x9_19)
	VPMULUDQ(outTmp[6], X9_19, Z5) // z5 = m(x6,x9_19)
	VPMULUDQ(X7_2, X9_19, Z6)      // z6 = m(x7_2,x9_19)
	VPMULUDQ(outTmp[8], X9_19, Z7) // z7 = m(x8,x9_19)
	VPMULUDQ(outTmp[9], X9_19, Z8) // z8 = m(x9,x9_19)
	X9_19 = nil

	Comment("(z5, z6, z7, z8) <<= 1 (results spilled)")
	VPADDQ(Z5, Z5, Z5) // z5 <<= 1
	VPADDQ(Z6, Z6, Z6) // z6 <<= 1
	VPADDQ(Z7, Z7, Z7) // z7 <<= 1
	VPADDQ(Z8, Z8, Z8) // z8 <<= 1
	VMOVDQA(Z5, tmp(0))
	VMOVDQA(Z6, tmp(1))
	VMOVDQA(Z7, tmp(2))
	VMOVDQA(Z8, tmp(3))

	Comment(
		"z0 += m(x3_2,x7_19)",
		"z1 += m(x4,x7_19)",
		"z2 += m(x5_2,x7_19)",
		"z3 += m(x6,x7_19)",
		"z4 += m(x7,x7_19)",
	)
	T0, T1, T2, T3, T4 := Z5, Z6, Z7, Z8, YMM()
	X7_19 := YMM()
	VMOVDQA(x(7), T4)
	VPMULUDQ(v19Reg, T4, X7_19)
	VPMULUDQ(X3_2, X7_19, T0) // t0 = m(x3_2,x7_19)
	VPMULUDQ(x(4), X7_19, T1) // t1 = m(x4,x7_19)
	VPMULUDQ(X5_2, X7_19, T2) // t2 = m(x5_2,x7_19)
	VPMULUDQ(x(6), X7_19, T3) // t3 = m(x6,x7_19)
	VPMULUDQ(T4, X7_19, T4)   // t4 = m(x7,x7_19)
	VPADDQ(Z0, T0, Z0)
	VPADDQ(Z1, T1, Z1)
	VPADDQ(Z2, T2, Z2)
	VPADDQ(Z3, T3, Z3)
	VPADDQ(Z4, T4, Z4)
	X7_19 = nil

	Comment("z0 += m(x5,x5_19)")
	X5_19 := YMM()
	VMOVDQA(x(5), T0)
	VPMULUDQ(v19Reg, T0, X5_19)
	VPMULUDQ(T0, X5_19, T0) // t0 = m(x5,x5_19)
	VPADDQ(Z0, T0, Z0)
	X5_19 = nil

	Comment("(z0 .. z4) <<= 1")
	VPADDQ(Z0, Z0, Z0) // z0 <<= 1
	VPADDQ(Z1, Z1, Z1) // z1 <<= 1
	VPADDQ(Z2, Z2, Z2) // z2 <<= 1
	VPADDQ(Z3, Z3, Z3) // z3 <<= 1
	VPADDQ(Z4, Z4, Z4) // z4 <<= 1

	Comment(
		"At this point:",
		"z0 = ((m(x1_2,x9_19) + m(x3_2,x7_19) + m(x5,x5_19)) << 1)",
		"z1 = ((m(x2,x9_19)   + m(x4,x7_19))                 << 1)",
		"z2 = ((m(x3_2,x9_19) + m(x5_2,x7_19))               << 1)",
		"z3 = ((m(x4,x9_19)   + m(x6,x7_19))                 << 1)",
		"z4 = ((m(x5_2,x9_19) + m(x7,x7_19))                 << 1)",
		"z5 = ((m(x6,x9_19))                                 << 1) (spilled)",
		"z6 = ((m(x7_2,x9_19))                               << 1) (spilled)",
		"z7 = ((m(x8,x9_19))                                 << 1) (spilled)",
		"z8 = ((m(x9,x9_19))                                 << 1) (spilled)",
		"z9 = undefined\n",
	)

	// This becomes a massive shitshow of fighting register pressure,
	// while trying to avoid having to recompute intermediaries.
	//
	// Hopefully avo's register allocator can save us a lot of pain,
	// though the grouping/ordering dates back to when this was done
	// by hand.

	Comment(
		"z2 += m(x6,x6_19)",
		"z4 += m(x6_2,x8_19)",
	)
	X6_19, X8_19 := YMM(), YMM()
	T2, T4 = YMM(), YMM()
	VMOVDQA(x(6), T2)
	VPMULUDQ(x(8), v19Reg, X8_19)
	VPMULUDQ(T2, v19Reg, X6_19)
	VPADDD(T2, T2, T4)
	VPMULUDQ(T2, X6_19, T2)
	VPMULUDQ(T4, X8_19, T4)
	VPADDQ(Z2, T2, Z2)
	VPADDQ(Z4, T4, Z4)
	v19Reg = nil

	Comment(
		"z1 += m(x5_2,x6_19)",
		"z3 += m(x5_2,x8_19)",
		"z0 += m(x4_2,x6_19)",
		"z2 += m(x4_2,x8_19)",
	)
	T0, T1, T2, T3 = YMM(), YMM(), YMM(), YMM()
	VMOVDQA(x(4), T2)
	VPADDQ(T2, T2, T2)
	VPMULUDQ(X5_2, X6_19, T1) // t1 = m(x5_2,x6_19)
	VPMULUDQ(X5_2, X8_19, T3) // t3 = m(x5_2,x8_19)
	VPMULUDQ(T2, X6_19, T0)   // t0 = m(x4_2,x6_19)
	VPMULUDQ(T2, X8_19, T2)   // t2 = m(x4_2,x8_19)
	VPADDQ(Z1, T1, Z1)
	VPADDQ(Z3, T3, Z3)
	VPADDQ(Z0, T0, Z0)
	VPADDQ(Z2, T2, Z2)
	X6_19 = nil

	Comment(
		"z0 += m(x2_2,x8_19)",
		"z1 += m(x3_2,x8_19)",
		"z4 += m(x2,x2)",
	)
	X2 := YMM()
	T0, T1, T4 = YMM(), YMM(), YMM()
	VMOVDQA(x(2), X2)
	VPADDD(X2, X2, T0)
	VPMULUDQ(T0, X8_19, T0)   // t0 = m(x2_2,x8_19)
	VPMULUDQ(X3_2, X8_19, T1) // t1 = m(x3_2,x8_19)
	VPMULUDQ(X2, X2, T4)      // t4 = m(x2,x2)
	VPADDQ(Z0, T0, Z0)
	VPADDQ(Z1, T1, Z1)
	VPADDQ(Z4, T4, Z4)

	Comment(
		"z2 += m(x1_2,x1)",
		"z3 += m(x1_2,x2)",
		"z4 += m(x1_2,x3_2)",
	)
	T2, T3, T4 = YMM(), YMM(), YMM()
	VPMULUDQ(x(1), X1_2, T2) // t1 = m(x1_2,x1)
	VPMULUDQ(X2, X1_2, T3)   // t3 = m(x1_2,x2)
	VPMULUDQ(X3_2, X1_2, T4) // t4 = m(x1_2,x3_2)
	VPADDQ(Z2, T2, Z2)
	VPADDQ(Z3, T3, Z3)
	VPADDQ(Z4, T4, Z4)

	Comment(
		"z0 += m(x0,x0)",
		"z1 += m(x0_2,x1)",
		"z2 += m(x0_2,x2)",
		"z3 += m(x0_2,x3)",
		"z4 += m(x0_2,x4)",
		"Note: (z0 .. z4) done at this point",
	)
	T0, T1, T2, T3, T4 = YMM(), YMM(), YMM(), YMM(), YMM()
	X0_2 := YMM()
	VMOVDQA(x(0), T0)
	VPADDD(T0, T0, X0_2)
	VPMULUDQ(T0, T0, T0)     // t0 = m(x0,x0)
	VPMULUDQ(x(1), X0_2, T1) // t1 = m(x0_2,x1)
	VPMULUDQ(X2, X0_2, T2)   // t2 = m(x0_2,x2)
	VPMULUDQ(x(3), X0_2, T3) // t3 = m(x0_2,x3)
	VPMULUDQ(x(4), X0_2, T4) // t4 = m(x0_2,x4)
	VPADDQ(Z0, T0, Z0)
	VPADDQ(Z1, T1, Z1)
	VPADDQ(Z2, T2, Z2)
	VPADDQ(Z3, T3, Z3)
	VPADDQ(Z4, T4, Z4)
	T0, T1, T2, T3, T4 = nil, nil, nil, nil, nil
	X2 = nil

	Comment(
		"z5 += m(x0_2,x5)",
		"z6 += m(x0_2,x6)",
		"z7 += m(x0_2,x7)",
		"z8 += m(x0_2,x8)",
		"z9 = m(x0_2,x9)",
	)
	Z5, Z6, Z7, Z8 = YMM(), YMM(), YMM(), YMM()
	Z9 := YMM()
	VPMULUDQ(x(5), X0_2, Z5) // t5 = m(x0_2,x5) (Yes, the variables are named Z)
	VPMULUDQ(x(6), X0_2, Z6) // t6 = m(x0_2,x6)
	VPMULUDQ(x(7), X0_2, Z7) // t7 = m(x0_2,x7)
	VPMULUDQ(x(8), X0_2, Z8) // t8 = m(x0_2,x8)
	VPMULUDQ(x(9), X0_2, Z9) // z9 = m(x0_2,x9)
	VPADDQ(tmp(0), Z5, Z5)
	VPADDQ(tmp(1), Z6, Z6)
	VPADDQ(tmp(2), Z7, Z7)
	VPADDQ(tmp(3), Z8, Z8)

	Comment(
		"Now that (z0 .. z4) are done, and we unspilled (z5 .. z8) as",
		"part of the previous group of multiply/adds, we spill (z0 .. z4)",
		"to free up registers.",
	)
	VMOVDQA(Z0, tmp(0))
	VMOVDQA(Z1, tmp(1))
	VMOVDQA(Z2, tmp(2))
	VMOVDQA(Z3, tmp(3))
	VMOVDQA(Z4, tmp(4))
	Z0, Z1, Z2, Z3, Z4 = nil, nil, nil, nil, nil

	Comment(
		"z5 += m(x1_2,x4)",
		"z6 += m(x1_2,x5_2)",
		"z7 += m(x1_2,x6)",
		"z8 += m(x1_2,x7_2)",
		"z9 += m(x1_2,x8)",
	)
	T5, T6, T7, T8, T9 := YMM(), YMM(), YMM(), YMM(), YMM()
	VPMULUDQ(x(4), X1_2, T5) // t5 = m(x1_2,x4)
	VPMULUDQ(X5_2, X1_2, T6) // t6 = m(x1_2,x5_2)
	VPMULUDQ(x(6), X1_2, T7) // t7 = m(x1_2,x6)
	VPMULUDQ(X7_2, X1_2, T8) // t8 = m(x1_2,x7_2)
	VPMULUDQ(x(8), X1_2, T9) // t9 = m(x1_2,x8)
	VPADDQ(Z5, T5, Z5)
	VPADDQ(Z6, T6, Z6)
	VPADDQ(Z7, T7, Z7)
	VPADDQ(Z8, T8, Z8)
	VPADDQ(Z9, T9, Z9)
	X1_2 = nil

	Comment(
		"z5 += m(x2_2,x3)",
		"z6 += m(x2_2,x4)",
		"z7 += m(x2_2,x5)",
		"z8 += m(x2_2,x6)",
		"z9 += m(x2_2,x7)",
	)
	X4, X2_2 := YMM(), YMM()
	VMOVDQA(x(4), X4)
	VMOVDQA(x(2), X2_2)
	VPADDD(X2_2, X2_2, X2_2) // Note: Better to recompute this than x8_19 probably.
	VPMULUDQ(x(3), X2_2, T5) // t5 = m(x2_2,x3)
	VPMULUDQ(X4, X2_2, T6)   // t6 = m(x2_2,x4)
	VPMULUDQ(x(5), X2_2, T7) // t7 = m(x2_2,x5)
	VPMULUDQ(x(6), X2_2, T8) // t8 = m(x2_2,x6)
	VPMULUDQ(x(7), X2_2, T9) // t9 = m(x2_2,x7)
	VPADDQ(Z5, T5, Z5)
	VPADDQ(Z6, T6, Z6)
	VPADDQ(Z7, T7, Z7)
	VPADDQ(Z8, T8, Z8)
	VPADDQ(Z9, T9, Z9)
	X2, X2_2 = nil, nil

	Comment(
		"z6 += m(x3_2,x3)",
		"z7 += m(x3_2,x4)",
		"z8 += m(x3_2,x5_2)",
		"z9 += m(x3_2,x6)",
	)
	VPMULUDQ(x(3), X3_2, T6) // t6 = m(x3_2,x3)
	VPMULUDQ(X4, X3_2, T7)   // t7 = m(x3_2,x4)
	VPMULUDQ(X5_2, X3_2, T8) // t8 = m(x3_2,x5_2)
	VPMULUDQ(x(6), X3_2, T9) // t9 = m(x3_2,x6)
	VPADDQ(Z6, T6, Z6)
	VPADDQ(Z7, T7, Z7)
	VPADDQ(Z8, T8, Z8)
	VPADDQ(Z9, T9, Z9)
	X3_2, X5_2 = nil, nil

	Comment(
		"z5 += m(x7_2,x8_19)",
		"z6 += m(x8,x8_19)",
		"z8 += m(x4,x4)",
		"z9 += m(x4_2,x5)",
	)
	X4_2 := YMM()
	VPADDD(X4, X4, X4_2)
	VPMULUDQ(X7_2, X8_19, T5) // t5 = m(x7_2,x8_19)
	VPMULUDQ(x(8), X8_19, T6) // t6 = m(x8,x8_19)
	VPMULUDQ(X4, X4, T8)      // t8 = m(x4,x4)
	VPMULUDQ(x(5), X4_2, T9)  // t9 = m(x4_2,x5)
	VPADDQ(Z5, T5, Z5)
	VPADDQ(Z6, T6, Z6)
	VPADDQ(Z8, T8, Z8)
	VPADDQ(Z9, T9, Z9)
	X7_2, X8_19 = nil, nil

	Comment("Restore the completed (z0, .., z4) from the stack")
	Z0, Z1, Z2, Z3, Z4 = YMM(), YMM(), YMM(), YMM(), YMM()
	VMOVDQA(tmp(0), Z0)
	VMOVDQA(tmp(1), Z1)
	VMOVDQA(tmp(2), Z2)
	VMOVDQA(tmp(3), Z3)
	VMOVDQA(tmp(4), Z4)

	toNegateD := vecPoint64{Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9}
	toNegateD.NegateD(out)

	VZEROUPPER()
	RET()

	return nil
}
