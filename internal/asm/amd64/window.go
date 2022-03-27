// Copyright (c) 2019-2021 Oasis Labs Inc. All rights reserved.
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
)

func main() {
	for i, step := range []func() error{
		SetCommon,
		LookupAffineNiels,
		LookupCached,
	} {
		if err := step(); err != nil {
			fmt.Printf("step %d failed: %v", i, err)
			os.Exit(1)
		}
	}

	Generate()
}

func LookupAffineNiels() error {
	TEXT(
		"lookupAffineNiels",
		NOSPLIT|NOFRAME,
		"func(table *affineNielsPointLookupTable, out *affineNielsPoint, xabs uint8)",
	)

	Comment(
		"This is moderately annoying due to having 3x5 64-bit elements,",
		"which does not nicely fit into vector registers.  This is",
		"handled by duplicating one element in 2 registers, since",
		"doing so keeps the rest of the code straight forward.",
		"",
		"v0 = y_plus_x[0],  y_plus_x[1]",
		"v1 = y_plus_x[2],  y_plus_x[3]",
		"v2 = y_plus_x[4],  y_minus_x[0]",
		"v3 = y_minus_x[1], y_minus_x[2]",
		"v4 = y_minus_x[3], y_minus_x[4]",
		"v5 = xy2d[0],      xy2d[1]",
		"v6 = xy2d[1] (*),  xy2d[2]",
		"v7 = xy2d[3],      xy2d[4]",
		"",
		"Note: Before I get tempted to rewrite this to use AVX2 again",
		"I will to take a moment to remind myself that the AVX2 backend",
		"does not use this table.\n",
	)

	tableReg := Load(Param("table"), GP64())
	table := Mem{Base: tableReg}

	Comment("Build the mask, zero all the registers")
	xabsVec, mask := XMM(), XMM()
	tmp := Load(Param("xabs"), GP64())
	MOVD(tmp, xabsVec)
	PSHUFD(Imm(0), xabsVec, xabsVec)

	v0, v1, v2, v3, v4, v5, v6, v7 := XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM()
	PXOR(v0, v0)
	PXOR(v1, v1)
	PXOR(v2, v2)
	PXOR(v3, v3)
	PXOR(v4, v4)
	PXOR(v5, v5)
	PXOR(v6, v6)
	PXOR(v7, v7)

	m0, m1, m2, m3, index := XMM(), XMM(), XMM(), XMM(), tmp
	makeMask := func() {
		MOVD(index, mask)
		PSHUFD(Imm(0), mask, mask)
		PCMPEQL(xabsVec, mask)
	}

	Comment("0: Identity element (1, 1, 0)")
	PXOR(mask, mask) // Skip the MOVQ, MOVD, PSHUFD that makeMask would do.
	PCMPEQL(xabsVec, mask)
	MOVQ(U64(1), tmp)
	MOVQ(tmp, m0) // m0 = uint64{1, 0} (y_plus_x[0], y_plus_x[1])
	PXOR(m1, m1)
	PUNPCKLQDQ(m0, m1) // m1 = uint64{0, 1} (y_plus_x[4], y_minus_x[0])
	PAND(mask, m0)
	PAND(mask, m1)
	POR(m0, v0)
	POR(m1, v2)

	Comment("1 .. 8")
	MOVQ(U64(1), index)

	Label("affine_lookup_loop")
	makeMask()
	MOVOU(table.Offset(0), m0)
	MOVOU(table.Offset(16), m1)
	MOVOU(table.Offset(32), m2)
	MOVOU(table.Offset(48), m3)
	PAND(mask, m0)
	PAND(mask, m1)
	PAND(mask, m2)
	PAND(mask, m3)
	POR(m0, v0)
	POR(m1, v1)
	POR(m2, v2)
	POR(m3, v3)
	MOVOU(table.Offset(64), m0)
	MOVOU(table.Offset(80), m1)
	MOVOU(table.Offset(88), m2) // Only incremented by 8 because of the duplicated element.
	MOVOU(table.Offset(104), m3)
	PAND(mask, m0)
	PAND(mask, m1)
	PAND(mask, m2)
	PAND(mask, m3)
	POR(m0, v4)
	POR(m1, v5)
	POR(m2, v6)
	POR(m3, v7)
	ADDQ(Imm(120), tableReg)
	INCQ(index)
	CMPQ(index, Imm(8))
	JLE(LabelRef("affine_lookup_loop"))

	Comment("Write out the result")
	out := Mem{Base: Load(Param("out"), GP64())}
	MOVOU(v0, out.Offset(0))
	MOVOU(v1, out.Offset(16))
	MOVOU(v2, out.Offset(32))
	MOVOU(v3, out.Offset(48))
	MOVOU(v4, out.Offset(64))
	MOVOU(v5, out.Offset(80))
	MOVOU(v6, out.Offset(88)) // De-duplicate the element.
	MOVOU(v7, out.Offset(104))

	RET()

	return nil
}

func LookupCached() error {
	cached_id_0 := newU32x8(
		"cached_id_0",
		[8]uint32{121647, 121666, 0, 0, 243332, 67108845, 0, 33554431},
	)
	cached_id_1 := newU32x8(
		"cached_id_1",
		[8]uint32{67108864, 0, 33554431, 0, 0, 67108863, 0, 33554431},
	)
	cached_id_2_4 := newU32x8(
		"cached_id_2_4",
		[8]uint32{67108863, 0, 33554431, 0, 0, 67108863, 0, 33554431},
	)

	TEXT(
		"lookupCached",
		NOSPLIT|NOFRAME,
		"func(table *cachedPointLookupTable, out *cachedPoint, xabs uint8)",
	)

	tableReg := Load(Param("table"), GP64())
	table := Mem{Base: tableReg}

	Comment("Build the mask, zero all the registers")
	xabsVec, mask := YMM(), YMM()
	tmpReg := GP64()
	tmp := Load(Param("xabs"), tmpReg)
	VMOVD(tmpReg.As32(), xabsVec.AsX())
	VPBROADCASTD(xabsVec.AsX(), xabsVec)

	v0, v1, v2, v3, v4 := YMM(), YMM(), YMM(), YMM(), YMM()
	VPXOR(v0, v0, v0)
	VPXOR(v1, v1, v1)
	VPXOR(v2, v2, v2)
	VPXOR(v3, v3, v3)
	VPXOR(v4, v4, v4)

	m0, m1, m2, m3, m4, index := YMM(), YMM(), YMM(), YMM(), YMM(), tmp
	makeMask := func() {
		VMOVQ(index, mask.AsX())
		VPBROADCASTD(mask.AsX(), mask)
		VPCMPEQD(xabsVec, mask, mask)
	}

	Comment("0: Identity element")
	VPXOR(mask, mask, mask) // Skip the MOVQ, VMOVD, VPBROADCASTD that makeMask would do.
	VPCMPEQD(xabsVec, mask, mask)
	VMOVDQA(cached_id_0, m0)
	VMOVDQA(cached_id_1, m1)
	VMOVDQA(cached_id_2_4, m2)
	VMOVDQA(m2, m3)
	VMOVDQA(m2, m4)
	VPAND(m0, mask, v0) // Can just write directly skipping VPORs, v0 .. v4 are all 0s.
	VPAND(m1, mask, v1)
	VPAND(m2, mask, v2)
	VPAND(m3, mask, v3)
	VPAND(m4, mask, v4)

	Comment("1 .. 8")
	MOVQ(U64(1), index)

	Label("cached_lookup_loop")
	makeMask()
	VPAND(table.Offset(0), mask, m0)
	VPAND(table.Offset(32), mask, m1)
	VPAND(table.Offset(64), mask, m2)
	VPAND(table.Offset(96), mask, m3)
	VPAND(table.Offset(128), mask, m4)
	VPOR(v0, m0, v0)
	VPOR(v1, m1, v1)
	VPOR(v2, m2, v2)
	VPOR(v3, m3, v3)
	VPOR(v4, m4, v4)
	ADDQ(Imm(160), tableReg)
	INCQ(index)
	CMPQ(index, Imm(8))
	JLE(LabelRef("cached_lookup_loop"))

	Comment("Write out the result")
	out := Mem{Base: Load(Param("out"), GP64())}
	VMOVDQU(v0, out.Offset(0))
	VMOVDQU(v1, out.Offset(32))
	VMOVDQU(v2, out.Offset(64))
	VMOVDQU(v3, out.Offset(96))
	VMOVDQU(v4, out.Offset(128))

	VZEROUPPER()
	RET()

	return nil
}
