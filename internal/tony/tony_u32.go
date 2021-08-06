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

//go:build (386 || arm || mips || mipsle || mips64le || mips64 || force32bit) && !force64bit
// +build 386 arm mips mipsle mips64le mips64 force32bit
// +build !force64bit

package tony

import fiat "github.com/mit-plv/fiat-crypto/fiat-go/32/curve25519"

type (
	TightFieldElement fiat.TightFieldElement
	LooseFieldElement fiat.LooseFieldElement
)

func (tfe *TightFieldElement) CarryMul(arg1, arg2 *LooseFieldElement) *TightFieldElement {
	fiat.CarryMul((*fiat.TightFieldElement)(tfe), (*fiat.LooseFieldElement)(arg1), (*fiat.LooseFieldElement)(arg2))
	return tfe
}

func (tfe *TightFieldElement) CarryMulAdd(arg1 *LooseFieldElement, arg2, arg3 *TightFieldElement) *TightFieldElement {
	var sum LooseFieldElement
	sum.Add(arg2, arg3)
	return tfe.CarryMul(arg1, &sum)
}

func (tfe *TightFieldElement) CarryMulSub(arg1 *LooseFieldElement, arg2, arg3 *TightFieldElement) *TightFieldElement {
	var diff LooseFieldElement
	diff.Sub(arg2, arg3)
	return tfe.CarryMul(arg1, &diff)
}

func (tfe *TightFieldElement) CarrySquare(arg1 *LooseFieldElement) *TightFieldElement {
	fiat.CarrySquare((*fiat.TightFieldElement)(tfe), (*fiat.LooseFieldElement)(arg1))
	return tfe
}

func (tfe *TightFieldElement) CarrySquareAdd(arg1, arg2 *TightFieldElement) *TightFieldElement {
	lfe := tfe.RelaxCast()
	lfe.Add(arg1, arg2)
	return tfe.CarrySquare(lfe)
}

func (tfe *TightFieldElement) CarrySquareSub(arg1, arg2 *TightFieldElement) *TightFieldElement {
	lfe := tfe.RelaxCast()
	lfe.Sub(arg1, arg2)
	return tfe.CarrySquare(lfe)
}

func (tfe *TightFieldElement) CarryPow2k(arg1 *LooseFieldElement, k uint) *TightFieldElement {
	if k == 0 {
		panic("internal/tony: k out of bounds")
	}

	tfe.CarrySquare(arg1)
	for i := uint(1); i < k; i++ {
		tfe.CarrySquare(tfe.RelaxCast())
	}

	return tfe
}

func (tfe *TightFieldElement) CarryScmul121666(arg1 *LooseFieldElement) *TightFieldElement {
	fiat.CarryScmul121666((*fiat.TightFieldElement)(tfe), (*fiat.LooseFieldElement)(arg1))
	return tfe
}

func (tfe *TightFieldElement) Carry(arg1 *LooseFieldElement) *TightFieldElement {
	fiat.Carry((*fiat.TightFieldElement)(tfe), (*fiat.LooseFieldElement)(arg1))
	return tfe
}

func (tfe *TightFieldElement) CarryAdd(arg1, arg2 *TightFieldElement) *TightFieldElement {
	fiat.CarryAdd((*fiat.TightFieldElement)(tfe), (*fiat.TightFieldElement)(arg1), (*fiat.TightFieldElement)(arg2))
	return tfe
}

func (tfe *TightFieldElement) CarrySub(arg1, arg2 *TightFieldElement) *TightFieldElement {
	fiat.CarrySub((*fiat.TightFieldElement)(tfe), (*fiat.TightFieldElement)(arg1), (*fiat.TightFieldElement)(arg2))
	return tfe
}

func (tfe *TightFieldElement) CarryOpp(arg1 *TightFieldElement) *TightFieldElement {
	fiat.CarryOpp((*fiat.TightFieldElement)(tfe), (*fiat.TightFieldElement)(arg1))
	return tfe
}

func (tfe *TightFieldElement) ToBytes(out1 *[32]uint8) {
	fiat.ToBytes(out1, (*fiat.TightFieldElement)(tfe))
}

func (tfe *TightFieldElement) FromBytes(arg1 *[32]uint8) {
	fiat.FromBytes((*fiat.TightFieldElement)(tfe), arg1)
}

func (lfe *LooseFieldElement) Add(arg1, arg2 *TightFieldElement) *LooseFieldElement {
	fiat.Add((*fiat.LooseFieldElement)(lfe), (*fiat.TightFieldElement)(arg1), (*fiat.TightFieldElement)(arg2))
	return lfe
}

func (lfe *LooseFieldElement) Sub(arg1, arg2 *TightFieldElement) *LooseFieldElement {
	fiat.Sub((*fiat.LooseFieldElement)(lfe), (*fiat.TightFieldElement)(arg1), (*fiat.TightFieldElement)(arg2))
	return lfe
}

func (lfe *LooseFieldElement) Opp(arg1 *TightFieldElement) *LooseFieldElement {
	fiat.Opp((*fiat.LooseFieldElement)(lfe), (*fiat.TightFieldElement)(arg1))
	return lfe
}

// Uint8ToLimb converts from a uint8 to a limb.
func Uint8ToLimb(i uint8) uint32 {
	return (uint32)(i)
}
