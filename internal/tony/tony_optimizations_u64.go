// The BSD 1-Clause License (BSD-1-Clause)
//
// Copyright (c) 2015-2020 the fiat-crypto authors (see the AUTHORS file)
// All rights reserved.
// Copyright (c) 2021 Oasis Labs Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
// THIS SOFTWARE IS PROVIDED BY the fiat-crypto authors "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Berkeley Software Design,
// Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//go:build (amd64 || arm64 || ppc64le || ppc64 || s390x || force64bit) && !force32bit
// +build amd64 arm64 ppc64le ppc64 s390x force64bit
// +build !force32bit

package tony

import "math/bits"

type (
	uint1 uint64
	int1  int64
)

//           W A R N I N G
//   ------------------------------
//         Om Marishi Sowaka
//   The big enemy is approaching
//   at full trottle.
//   According to the data, it is
//   identified as "Optimizations".
//   ------------------------------
//             NO REFUGE
//
// There really isn't anything wrong with the fiat-crypto Go code.
// There is however, lots of things that are wrong with the Go compiler.
//
//  * The inliner is awful, and there is no way to force inlining
//    (golang/go#21536).  In addition to the fused `Add`/`Sub`/`Opp`
//    + `Carry` that upstream added for us, this does even more manual
//    inlining.
//
//    * CarryMulAdd `a * (b + c)`
//    * CarryMulSub `a * (b - c)`
//    * CarryPow2k `a^(2k)`, where `k > 0`.  This is probably the one
//      case where it is unreasonable to expect the compiler to auto
//      inline the routine.  This also is the most impactful, as it
//      dramatically improves inverson/sqrt performance.
//    * cmovznzU64/addcarryxU51/subborrowxU51 function signature changed
//      to speed up ToBytes.
//
// The dream is that eventually this file will go away entirely, but
// it's hard to get away from needing manual inlining.
//

func carryMulAddInlined(out1 *TightFieldElement, arg1 *LooseFieldElement, arg2, arg3 *TightFieldElement) {
	// Add (arg2 + arg3)
	a0 := (arg2[0] + arg3[0])
	a1 := (arg2[1] + arg3[1])
	a2 := (arg2[2] + arg3[2])
	a3 := (arg2[3] + arg3[3])
	a4 := (arg2[4] + arg3[4])

	// Mul (arg1 * (arg2 + arg3))
	var x1 uint64
	var x2 uint64
	x2, x1 = bits.Mul64(arg1[4], (a4 * 0x13))
	var x3 uint64
	var x4 uint64
	x4, x3 = bits.Mul64(arg1[4], (a3 * 0x13))
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(arg1[4], (a2 * 0x13))
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(arg1[4], (a1 * 0x13))
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(arg1[3], (a4 * 0x13))
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(arg1[3], (a3 * 0x13))
	var x13 uint64
	var x14 uint64
	x14, x13 = bits.Mul64(arg1[3], (a2 * 0x13))
	var x15 uint64
	var x16 uint64
	x16, x15 = bits.Mul64(arg1[2], (a4 * 0x13))
	var x17 uint64
	var x18 uint64
	x18, x17 = bits.Mul64(arg1[2], (a3 * 0x13))
	var x19 uint64
	var x20 uint64
	x20, x19 = bits.Mul64(arg1[1], (a4 * 0x13))
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(arg1[4], a0)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(arg1[3], a1)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(arg1[3], a0)
	var x27 uint64
	var x28 uint64
	x28, x27 = bits.Mul64(arg1[2], a2)
	var x29 uint64
	var x30 uint64
	x30, x29 = bits.Mul64(arg1[2], a1)
	var x31 uint64
	var x32 uint64
	x32, x31 = bits.Mul64(arg1[2], a0)
	var x33 uint64
	var x34 uint64
	x34, x33 = bits.Mul64(arg1[1], a3)
	var x35 uint64
	var x36 uint64
	x36, x35 = bits.Mul64(arg1[1], a2)
	var x37 uint64
	var x38 uint64
	x38, x37 = bits.Mul64(arg1[1], a1)
	var x39 uint64
	var x40 uint64
	x40, x39 = bits.Mul64(arg1[1], a0)
	var x41 uint64
	var x42 uint64
	x42, x41 = bits.Mul64(arg1[0], a4)
	var x43 uint64
	var x44 uint64
	x44, x43 = bits.Mul64(arg1[0], a3)
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(arg1[0], a2)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(arg1[0], a1)
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(arg1[0], a0)
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x13, x7, uint64(0x0))
	var x53 uint64
	x53, _ = bits.Add64(x14, x8, uint64(uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x17, x51, uint64(0x0))
	var x57 uint64
	x57, _ = bits.Add64(x18, x53, uint64(uint1(x56)))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(x19, x55, uint64(0x0))
	var x61 uint64
	x61, _ = bits.Add64(x20, x57, uint64(uint1(x60)))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x49, x59, uint64(0x0))
	var x65 uint64
	x65, _ = bits.Add64(x50, x61, uint64(uint1(x64)))
	x67 := ((x63 >> 51) | ((x65 << 13) & 0xffffffffffffffff))
	x68 := (x63 & 0x7ffffffffffff)
	var x69 uint64
	var x70 uint64
	x69, x70 = bits.Add64(x23, x21, uint64(0x0))
	var x71 uint64
	x71, _ = bits.Add64(x24, x22, uint64(uint1(x70)))
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x27, x69, uint64(0x0))
	var x75 uint64
	x75, _ = bits.Add64(x28, x71, uint64(uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x33, x73, uint64(0x0))
	var x79 uint64
	x79, _ = bits.Add64(x34, x75, uint64(uint1(x78)))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x41, x77, uint64(0x0))
	var x83 uint64
	x83, _ = bits.Add64(x42, x79, uint64(uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x25, x1, uint64(0x0))
	var x87 uint64
	x87, _ = bits.Add64(x26, x2, uint64(uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x29, x85, uint64(0x0))
	var x91 uint64
	x91, _ = bits.Add64(x30, x87, uint64(uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x35, x89, uint64(0x0))
	var x95 uint64
	x95, _ = bits.Add64(x36, x91, uint64(uint1(x94)))
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x43, x93, uint64(0x0))
	var x99 uint64
	x99, _ = bits.Add64(x44, x95, uint64(uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x9, x3, uint64(0x0))
	var x103 uint64
	x103, _ = bits.Add64(x10, x4, uint64(uint1(x102)))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x31, x101, uint64(0x0))
	var x107 uint64
	x107, _ = bits.Add64(x32, x103, uint64(uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x37, x105, uint64(0x0))
	var x111 uint64
	x111, _ = bits.Add64(x38, x107, uint64(uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x45, x109, uint64(0x0))
	var x115 uint64
	x115, _ = bits.Add64(x46, x111, uint64(uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x11, x5, uint64(0x0))
	var x119 uint64
	x119, _ = bits.Add64(x12, x6, uint64(uint1(x118)))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x15, x117, uint64(0x0))
	var x123 uint64
	x123, _ = bits.Add64(x16, x119, uint64(uint1(x122)))
	var x125 uint64
	var x126 uint64
	x125, x126 = bits.Add64(x39, x121, uint64(0x0))
	var x127 uint64
	x127, _ = bits.Add64(x40, x123, uint64(uint1(x126)))
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x47, x125, uint64(0x0))
	var x131 uint64
	x131, _ = bits.Add64(x48, x127, uint64(uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x67, x129, uint64(0x0))
	x135 := (uint64(uint1(x134)) + x131)
	x136 := ((x133 >> 51) | ((x135 << 13) & 0xffffffffffffffff))
	x137 := (x133 & 0x7ffffffffffff)
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x136, x113, uint64(0x0))
	x140 := (uint64(uint1(x139)) + x115)
	x141 := ((x138 >> 51) | ((x140 << 13) & 0xffffffffffffffff))
	x142 := (x138 & 0x7ffffffffffff)
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x141, x97, uint64(0x0))
	x145 := (uint64(uint1(x144)) + x99)
	x146 := ((x143 >> 51) | ((x145 << 13) & 0xffffffffffffffff))
	x147 := (x143 & 0x7ffffffffffff)
	var x148 uint64
	var x149 uint64
	x148, x149 = bits.Add64(x146, x81, uint64(0x0))
	x150 := (uint64(uint1(x149)) + x83)
	x151 := ((x148 >> 51) | ((x150 << 13) & 0xffffffffffffffff))
	x152 := (x148 & 0x7ffffffffffff)
	x153 := (x151 * 0x13)
	x154 := (x68 + x153)
	x155 := (x154 >> 51)
	x156 := (x154 & 0x7ffffffffffff)
	x157 := (x155 + x137)
	x158 := uint1((x157 >> 51))
	x159 := (x157 & 0x7ffffffffffff)
	x160 := (uint64(x158) + x142)
	out1[0] = x156
	out1[1] = x159
	out1[2] = x160
	out1[3] = x147
	out1[4] = x152
}

func carryMulSubInlined(out1 *TightFieldElement, arg1 *LooseFieldElement, arg2, arg3 *TightFieldElement) {
	// Sub (arg2 - arg3)
	a0 := ((0xfffffffffffda + arg2[0]) - arg3[0])
	a1 := ((0xffffffffffffe + arg2[1]) - arg3[1])
	a2 := ((0xffffffffffffe + arg2[2]) - arg3[2])
	a3 := ((0xffffffffffffe + arg2[3]) - arg3[3])
	a4 := ((0xffffffffffffe + arg2[4]) - arg3[4])

	// Mul (arg1 * (arg2 - arg3))
	var x1 uint64
	var x2 uint64
	x2, x1 = bits.Mul64(arg1[4], (a4 * 0x13))
	var x3 uint64
	var x4 uint64
	x4, x3 = bits.Mul64(arg1[4], (a3 * 0x13))
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(arg1[4], (a2 * 0x13))
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(arg1[4], (a1 * 0x13))
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(arg1[3], (a4 * 0x13))
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(arg1[3], (a3 * 0x13))
	var x13 uint64
	var x14 uint64
	x14, x13 = bits.Mul64(arg1[3], (a2 * 0x13))
	var x15 uint64
	var x16 uint64
	x16, x15 = bits.Mul64(arg1[2], (a4 * 0x13))
	var x17 uint64
	var x18 uint64
	x18, x17 = bits.Mul64(arg1[2], (a3 * 0x13))
	var x19 uint64
	var x20 uint64
	x20, x19 = bits.Mul64(arg1[1], (a4 * 0x13))
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(arg1[4], a0)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(arg1[3], a1)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(arg1[3], a0)
	var x27 uint64
	var x28 uint64
	x28, x27 = bits.Mul64(arg1[2], a2)
	var x29 uint64
	var x30 uint64
	x30, x29 = bits.Mul64(arg1[2], a1)
	var x31 uint64
	var x32 uint64
	x32, x31 = bits.Mul64(arg1[2], a0)
	var x33 uint64
	var x34 uint64
	x34, x33 = bits.Mul64(arg1[1], a3)
	var x35 uint64
	var x36 uint64
	x36, x35 = bits.Mul64(arg1[1], a2)
	var x37 uint64
	var x38 uint64
	x38, x37 = bits.Mul64(arg1[1], a1)
	var x39 uint64
	var x40 uint64
	x40, x39 = bits.Mul64(arg1[1], a0)
	var x41 uint64
	var x42 uint64
	x42, x41 = bits.Mul64(arg1[0], a4)
	var x43 uint64
	var x44 uint64
	x44, x43 = bits.Mul64(arg1[0], a3)
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(arg1[0], a2)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(arg1[0], a1)
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(arg1[0], a0)
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x13, x7, uint64(0x0))
	var x53 uint64
	x53, _ = bits.Add64(x14, x8, uint64(uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x17, x51, uint64(0x0))
	var x57 uint64
	x57, _ = bits.Add64(x18, x53, uint64(uint1(x56)))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(x19, x55, uint64(0x0))
	var x61 uint64
	x61, _ = bits.Add64(x20, x57, uint64(uint1(x60)))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x49, x59, uint64(0x0))
	var x65 uint64
	x65, _ = bits.Add64(x50, x61, uint64(uint1(x64)))
	x67 := ((x63 >> 51) | ((x65 << 13) & 0xffffffffffffffff))
	x68 := (x63 & 0x7ffffffffffff)
	var x69 uint64
	var x70 uint64
	x69, x70 = bits.Add64(x23, x21, uint64(0x0))
	var x71 uint64
	x71, _ = bits.Add64(x24, x22, uint64(uint1(x70)))
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x27, x69, uint64(0x0))
	var x75 uint64
	x75, _ = bits.Add64(x28, x71, uint64(uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x33, x73, uint64(0x0))
	var x79 uint64
	x79, _ = bits.Add64(x34, x75, uint64(uint1(x78)))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x41, x77, uint64(0x0))
	var x83 uint64
	x83, _ = bits.Add64(x42, x79, uint64(uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x25, x1, uint64(0x0))
	var x87 uint64
	x87, _ = bits.Add64(x26, x2, uint64(uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x29, x85, uint64(0x0))
	var x91 uint64
	x91, _ = bits.Add64(x30, x87, uint64(uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x35, x89, uint64(0x0))
	var x95 uint64
	x95, _ = bits.Add64(x36, x91, uint64(uint1(x94)))
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x43, x93, uint64(0x0))
	var x99 uint64
	x99, _ = bits.Add64(x44, x95, uint64(uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x9, x3, uint64(0x0))
	var x103 uint64
	x103, _ = bits.Add64(x10, x4, uint64(uint1(x102)))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x31, x101, uint64(0x0))
	var x107 uint64
	x107, _ = bits.Add64(x32, x103, uint64(uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x37, x105, uint64(0x0))
	var x111 uint64
	x111, _ = bits.Add64(x38, x107, uint64(uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x45, x109, uint64(0x0))
	var x115 uint64
	x115, _ = bits.Add64(x46, x111, uint64(uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x11, x5, uint64(0x0))
	var x119 uint64
	x119, _ = bits.Add64(x12, x6, uint64(uint1(x118)))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x15, x117, uint64(0x0))
	var x123 uint64
	x123, _ = bits.Add64(x16, x119, uint64(uint1(x122)))
	var x125 uint64
	var x126 uint64
	x125, x126 = bits.Add64(x39, x121, uint64(0x0))
	var x127 uint64
	x127, _ = bits.Add64(x40, x123, uint64(uint1(x126)))
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x47, x125, uint64(0x0))
	var x131 uint64
	x131, _ = bits.Add64(x48, x127, uint64(uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x67, x129, uint64(0x0))
	x135 := (uint64(uint1(x134)) + x131)
	x136 := ((x133 >> 51) | ((x135 << 13) & 0xffffffffffffffff))
	x137 := (x133 & 0x7ffffffffffff)
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x136, x113, uint64(0x0))
	x140 := (uint64(uint1(x139)) + x115)
	x141 := ((x138 >> 51) | ((x140 << 13) & 0xffffffffffffffff))
	x142 := (x138 & 0x7ffffffffffff)
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x141, x97, uint64(0x0))
	x145 := (uint64(uint1(x144)) + x99)
	x146 := ((x143 >> 51) | ((x145 << 13) & 0xffffffffffffffff))
	x147 := (x143 & 0x7ffffffffffff)
	var x148 uint64
	var x149 uint64
	x148, x149 = bits.Add64(x146, x81, uint64(0x0))
	x150 := (uint64(uint1(x149)) + x83)
	x151 := ((x148 >> 51) | ((x150 << 13) & 0xffffffffffffffff))
	x152 := (x148 & 0x7ffffffffffff)
	x153 := (x151 * 0x13)
	x154 := (x68 + x153)
	x155 := (x154 >> 51)
	x156 := (x154 & 0x7ffffffffffff)
	x157 := (x155 + x137)
	x158 := uint1((x157 >> 51))
	x159 := (x157 & 0x7ffffffffffff)
	x160 := (uint64(x158) + x142)
	out1[0] = x156
	out1[1] = x159
	out1[2] = x160
	out1[3] = x147
	out1[4] = x152
}

func carryPow2kInlined(out1 *TightFieldElement, arg1 *LooseFieldElement, arg2 uint) {
	a0, a1, a2, a3, a4 := arg1[0], arg1[1], arg1[2], arg1[3], arg1[4]

	for {
		x1 := (a4 * 0x13)
		x2 := (x1 * 0x2)
		x3 := (a4 * 0x2)
		x4 := (a3 * 0x13)
		x5 := (x4 * 0x2)
		x6 := (a3 * 0x2)
		x7 := (a2 * 0x2)
		x8 := (a1 * 0x2)
		var x9 uint64
		var x10 uint64
		x10, x9 = bits.Mul64(a4, x1)
		var x11 uint64
		var x12 uint64
		x12, x11 = bits.Mul64(a3, x2)
		var x13 uint64
		var x14 uint64
		x14, x13 = bits.Mul64(a3, x4)
		var x15 uint64
		var x16 uint64
		x16, x15 = bits.Mul64(a2, x2)
		var x17 uint64
		var x18 uint64
		x18, x17 = bits.Mul64(a2, x5)
		var x19 uint64
		var x20 uint64
		x20, x19 = bits.Mul64(a2, a2)
		var x21 uint64
		var x22 uint64
		x22, x21 = bits.Mul64(a1, x2)
		var x23 uint64
		var x24 uint64
		x24, x23 = bits.Mul64(a1, x6)
		var x25 uint64
		var x26 uint64
		x26, x25 = bits.Mul64(a1, x7)
		var x27 uint64
		var x28 uint64
		x28, x27 = bits.Mul64(a1, a1)
		var x29 uint64
		var x30 uint64
		x30, x29 = bits.Mul64(a0, x3)
		var x31 uint64
		var x32 uint64
		x32, x31 = bits.Mul64(a0, x6)
		var x33 uint64
		var x34 uint64
		x34, x33 = bits.Mul64(a0, x7)
		var x35 uint64
		var x36 uint64
		x36, x35 = bits.Mul64(a0, x8)
		var x37 uint64
		var x38 uint64
		x38, x37 = bits.Mul64(a0, a0)
		var x39 uint64
		var x40 uint64
		x39, x40 = bits.Add64(x21, x17, uint64(0x0))
		var x41 uint64
		x41, _ = bits.Add64(x22, x18, uint64(uint1(x40)))
		var x43 uint64
		var x44 uint64
		x43, x44 = bits.Add64(x37, x39, uint64(0x0))
		var x45 uint64
		x45, _ = bits.Add64(x38, x41, uint64(uint1(x44)))
		x47 := ((x43 >> 51) | ((x45 << 13) & 0xffffffffffffffff))
		x48 := (x43 & 0x7ffffffffffff)
		var x49 uint64
		var x50 uint64
		x49, x50 = bits.Add64(x23, x19, uint64(0x0))
		var x51 uint64
		x51, _ = bits.Add64(x24, x20, uint64(uint1(x50)))
		var x53 uint64
		var x54 uint64
		x53, x54 = bits.Add64(x29, x49, uint64(0x0))
		var x55 uint64
		x55, _ = bits.Add64(x30, x51, uint64(uint1(x54)))
		var x57 uint64
		var x58 uint64
		x57, x58 = bits.Add64(x25, x9, uint64(0x0))
		var x59 uint64
		x59, _ = bits.Add64(x26, x10, uint64(uint1(x58)))
		var x61 uint64
		var x62 uint64
		x61, x62 = bits.Add64(x31, x57, uint64(0x0))
		var x63 uint64
		x63, _ = bits.Add64(x32, x59, uint64(uint1(x62)))
		var x65 uint64
		var x66 uint64
		x65, x66 = bits.Add64(x27, x11, uint64(0x0))
		var x67 uint64
		x67, _ = bits.Add64(x28, x12, uint64(uint1(x66)))
		var x69 uint64
		var x70 uint64
		x69, x70 = bits.Add64(x33, x65, uint64(0x0))
		var x71 uint64
		x71, _ = bits.Add64(x34, x67, uint64(uint1(x70)))
		var x73 uint64
		var x74 uint64
		x73, x74 = bits.Add64(x15, x13, uint64(0x0))
		var x75 uint64
		x75, _ = bits.Add64(x16, x14, uint64(uint1(x74)))
		var x77 uint64
		var x78 uint64
		x77, x78 = bits.Add64(x35, x73, uint64(0x0))
		var x79 uint64
		x79, _ = bits.Add64(x36, x75, uint64(uint1(x78)))
		var x81 uint64
		var x82 uint64
		x81, x82 = bits.Add64(x47, x77, uint64(0x0))
		x83 := (uint64(uint1(x82)) + x79)
		x84 := ((x81 >> 51) | ((x83 << 13) & 0xffffffffffffffff))
		x85 := (x81 & 0x7ffffffffffff)
		var x86 uint64
		var x87 uint64
		x86, x87 = bits.Add64(x84, x69, uint64(0x0))
		x88 := (uint64(uint1(x87)) + x71)
		x89 := ((x86 >> 51) | ((x88 << 13) & 0xffffffffffffffff))
		x90 := (x86 & 0x7ffffffffffff)
		var x91 uint64
		var x92 uint64
		x91, x92 = bits.Add64(x89, x61, uint64(0x0))
		x93 := (uint64(uint1(x92)) + x63)
		x94 := ((x91 >> 51) | ((x93 << 13) & 0xffffffffffffffff))
		x95 := (x91 & 0x7ffffffffffff)
		var x96 uint64
		var x97 uint64
		x96, x97 = bits.Add64(x94, x53, uint64(0x0))
		x98 := (uint64(uint1(x97)) + x55)
		x99 := ((x96 >> 51) | ((x98 << 13) & 0xffffffffffffffff))
		x100 := (x96 & 0x7ffffffffffff)
		x101 := (x99 * 0x13)
		x102 := (x48 + x101)
		x103 := (x102 >> 51)
		x104 := (x102 & 0x7ffffffffffff)
		x105 := (x103 + x85)
		x106 := uint1((x105 >> 51))
		x107 := (x105 & 0x7ffffffffffff)
		x108 := (uint64(x106) + x90)
		a0 = x104
		a1 = x107
		a2 = x108
		a3 = x95
		a4 = x100

		arg2--
		if arg2 == 0 {
			break
		}
	}

	out1[0], out1[1], out1[2], out1[3], out1[4] = a0, a1, a2, a3, a4
}

func cmovznzU64(arg1 uint1, arg2 uint64, arg3 uint64) uint64 {
	x1 := (uint64(arg1) * 0xffffffffffffffff)
	return ((x1 & arg3) | ((^x1) & arg2))
}

func addcarryxU51(arg1 uint1, arg2 uint64, arg3 uint64) (out1 uint64, out2 uint1) {
	x1 := ((uint64(arg1) + arg2) + arg3)
	x2 := (x1 & 0x7ffffffffffff)
	x3 := uint1((x1 >> 51))
	return x2, x3
}

func subborrowxU51(arg1 uint1, arg2 uint64, arg3 uint64) (out1 uint64, out2 uint1) {
	x1 := ((int64(arg2) - int64(arg1)) - int64(arg3))
	x2 := int1((x1 >> 51))
	x3 := (uint64(x1) & 0x7ffffffffffff)
	return x3, (0x0 - uint1(x2))
}

func toBytesInlined(out1 *[32]uint8, arg1 *TightFieldElement) {
	x1, x2 := subborrowxU51(0x0, arg1[0], 0x7ffffffffffed)
	x3, x4 := subborrowxU51(x2, arg1[1], 0x7ffffffffffff)
	x5, x6 := subborrowxU51(x4, arg1[2], 0x7ffffffffffff)
	x7, x8 := subborrowxU51(x6, arg1[3], 0x7ffffffffffff)
	x9, x10 := subborrowxU51(x8, arg1[4], 0x7ffffffffffff)
	x11 := cmovznzU64(x10, uint64(0x0), 0xffffffffffffffff)
	x12, x13 := addcarryxU51(0x0, x1, (x11 & 0x7ffffffffffed))
	x14, x15 := addcarryxU51(x13, x3, (x11 & 0x7ffffffffffff))
	x16, x17 := addcarryxU51(x15, x5, (x11 & 0x7ffffffffffff))
	x18, x19 := addcarryxU51(x17, x7, (x11 & 0x7ffffffffffff))
	x20, _ := addcarryxU51(x19, x9, (x11 & 0x7ffffffffffff)) // x21 unused
	x22 := (x20 << 4)
	x23 := (x18 * uint64(0x2))
	x24 := (x16 << 6)
	x25 := (x14 << 3)
	x26 := (uint8(x12) & 0xff)
	x27 := (x12 >> 8)
	x28 := (uint8(x27) & 0xff)
	x29 := (x27 >> 8)
	x30 := (uint8(x29) & 0xff)
	x31 := (x29 >> 8)
	x32 := (uint8(x31) & 0xff)
	x33 := (x31 >> 8)
	x34 := (uint8(x33) & 0xff)
	x35 := (x33 >> 8)
	x36 := (uint8(x35) & 0xff)
	x37 := uint8((x35 >> 8))
	x38 := (x25 + uint64(x37))
	x39 := (uint8(x38) & 0xff)
	x40 := (x38 >> 8)
	x41 := (uint8(x40) & 0xff)
	x42 := (x40 >> 8)
	x43 := (uint8(x42) & 0xff)
	x44 := (x42 >> 8)
	x45 := (uint8(x44) & 0xff)
	x46 := (x44 >> 8)
	x47 := (uint8(x46) & 0xff)
	x48 := (x46 >> 8)
	x49 := (uint8(x48) & 0xff)
	x50 := uint8((x48 >> 8))
	x51 := (x24 + uint64(x50))
	x52 := (uint8(x51) & 0xff)
	x53 := (x51 >> 8)
	x54 := (uint8(x53) & 0xff)
	x55 := (x53 >> 8)
	x56 := (uint8(x55) & 0xff)
	x57 := (x55 >> 8)
	x58 := (uint8(x57) & 0xff)
	x59 := (x57 >> 8)
	x60 := (uint8(x59) & 0xff)
	x61 := (x59 >> 8)
	x62 := (uint8(x61) & 0xff)
	x63 := (x61 >> 8)
	x64 := (uint8(x63) & 0xff)
	x65 := uint1((x63 >> 8))
	x66 := (x23 + uint64(x65))
	x67 := (uint8(x66) & 0xff)
	x68 := (x66 >> 8)
	x69 := (uint8(x68) & 0xff)
	x70 := (x68 >> 8)
	x71 := (uint8(x70) & 0xff)
	x72 := (x70 >> 8)
	x73 := (uint8(x72) & 0xff)
	x74 := (x72 >> 8)
	x75 := (uint8(x74) & 0xff)
	x76 := (x74 >> 8)
	x77 := (uint8(x76) & 0xff)
	x78 := uint8((x76 >> 8))
	x79 := (x22 + uint64(x78))
	x80 := (uint8(x79) & 0xff)
	x81 := (x79 >> 8)
	x82 := (uint8(x81) & 0xff)
	x83 := (x81 >> 8)
	x84 := (uint8(x83) & 0xff)
	x85 := (x83 >> 8)
	x86 := (uint8(x85) & 0xff)
	x87 := (x85 >> 8)
	x88 := (uint8(x87) & 0xff)
	x89 := (x87 >> 8)
	x90 := (uint8(x89) & 0xff)
	x91 := uint8((x89 >> 8))
	out1[0] = x26
	out1[1] = x28
	out1[2] = x30
	out1[3] = x32
	out1[4] = x34
	out1[5] = x36
	out1[6] = x39
	out1[7] = x41
	out1[8] = x43
	out1[9] = x45
	out1[10] = x47
	out1[11] = x49
	out1[12] = x52
	out1[13] = x54
	out1[14] = x56
	out1[15] = x58
	out1[16] = x60
	out1[17] = x62
	out1[18] = x64
	out1[19] = x67
	out1[20] = x69
	out1[21] = x71
	out1[22] = x73
	out1[23] = x75
	out1[24] = x77
	out1[25] = x80
	out1[26] = x82
	out1[27] = x84
	out1[28] = x86
	out1[29] = x88
	out1[30] = x90
	out1[31] = x91
}
