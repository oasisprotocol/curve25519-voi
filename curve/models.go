// Copyright (c) 2016-2019 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
// Copyright (c) 2020-2021 Oasis Labs Inc.  All rights reserved.
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

package curve

import "github.com/oasisprotocol/curve25519-voi/internal/field"

//nolint:unused,deadcode,varcheck
var identityAffineNielsPacked = [96]byte{
	// y_plus_x = 1
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	// y_minus_x = 1
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	// xy2d = 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

type projectivePoint struct {
	X field.FieldElement
	Y field.FieldElement
	Z field.FieldElement
}

type completedPoint struct {
	X field.FieldElement
	Y field.FieldElement
	Z field.FieldElement
	T field.FieldElement
}

type affineNielsPoint struct {
	y_plus_x  field.FieldElement
	y_minus_x field.FieldElement
	xy2d      field.FieldElement
}

type projectiveNielsPoint struct {
	Y_plus_X  field.FieldElement
	Y_minus_X field.FieldElement
	Z         field.FieldElement
	T2d       field.FieldElement
}

// Note: dalek has the identity point as the defaut ctors for
// ProjectiveNielsPoint/AffineNielsPoint.

func (p *projectivePoint) identity() {
	p.X.Zero()
	p.Y.One()
	p.Z.One()
}

func (p *affineNielsPoint) identity() {
	p.y_plus_x.One()
	p.y_minus_x.One()
	p.xy2d.Zero()
}

//nolint:unused
func (p *projectiveNielsPoint) identity() {
	p.Y_plus_X.One()
	p.Y_minus_X.One()
	p.Z.One()
	p.T2d.Zero()
}

func (p *projectivePoint) debugIsValid() bool {
	// Curve equation is    -x^2 + y^2 = 1 + d*x^2*y^2,
	// homogenized as (-X^2 + Y^2)*Z^2 = Z^4 + d*X^2*Y^2
	XX := p.X
	XX.Square()
	YY := p.Y
	YY.Square()
	ZZ := p.Z
	ZZ.Square()
	ZZZZ := ZZ
	ZZZZ.Square()

	var lhs, rhs field.FieldElement
	lhs.Sub(&YY, &XX)
	lhs.Mul(&lhs, &ZZ)
	rhs.Mul(&XX, &YY)
	rhs.Mul(&rhs, &constEDWARDS_D)
	rhs.Add(&rhs, &ZZZZ)

	return lhs.Equal(&rhs) == 1
}

//nolint:unused
func (p *projectiveNielsPoint) conditionalSelect(a, b *projectiveNielsPoint, choice int) {
	p.Y_plus_X.ConditionalSelect(&a.Y_plus_X, &b.Y_plus_X, choice)
	p.Y_minus_X.ConditionalSelect(&a.Y_minus_X, &b.Y_minus_X, choice)
	p.Z.ConditionalSelect(&a.Z, &b.Z, choice)
	p.T2d.ConditionalSelect(&a.T2d, &b.T2d, choice)
}

func (p *projectiveNielsPoint) conditionalAssign(other *projectiveNielsPoint, choice int) {
	p.Y_plus_X.ConditionalAssign(&other.Y_plus_X, choice)
	p.Y_minus_X.ConditionalAssign(&other.Y_minus_X, choice)
	p.Z.ConditionalAssign(&other.Z, choice)
	p.T2d.ConditionalAssign(&other.T2d, choice)
}

//nolint:unused
func (p *affineNielsPoint) conditionalSelect(a, b *affineNielsPoint, choice int) {
	p.y_plus_x.ConditionalSelect(&a.y_plus_x, &b.y_plus_x, choice)
	p.y_minus_x.ConditionalSelect(&a.y_minus_x, &b.y_minus_x, choice)
	p.xy2d.ConditionalSelect(&a.xy2d, &b.xy2d, choice)
}

func (p *affineNielsPoint) conditionalAssign(other *affineNielsPoint, choice int) {
	p.y_plus_x.ConditionalAssign(&other.y_plus_x, choice)
	p.y_minus_x.ConditionalAssign(&other.y_minus_x, choice)
	p.xy2d.ConditionalAssign(&other.xy2d, choice)
}

func (p *EdwardsPoint) fromProjective(pp *projectivePoint) {
	p.inner.X.Mul(&pp.X, &pp.Z)
	p.inner.Y.Mul(&pp.Y, &pp.Z)
	p.inner.Z = pp.Z
	p.inner.Z.Square()
	p.inner.T.Mul(&pp.X, &pp.Y)
}

func (p *EdwardsPoint) fromCompleted(cp *completedPoint) {
	p.inner.X.Mul(&cp.X, &cp.T)
	p.inner.Y.Mul(&cp.Y, &cp.Z)
	p.inner.Z.Mul(&cp.Z, &cp.T)
	p.inner.T.Mul(&cp.X, &cp.Y)
}

func (p *projectivePoint) fromCompleted(cp *completedPoint) {
	p.X.Mul(&cp.X, &cp.T)
	p.Y.Mul(&cp.Y, &cp.Z)
	p.Z.Mul(&cp.Z, &cp.T)
}

func (p *projectivePoint) fromEdwards(ep *EdwardsPoint) {
	p.X = ep.inner.X
	p.Y = ep.inner.Y
	p.Z = ep.inner.Z
}

func (p *projectiveNielsPoint) fromEdwards(ep *EdwardsPoint) {
	p.Y_plus_X.Add(&ep.inner.Y, &ep.inner.X)
	p.Y_minus_X.Sub(&ep.inner.Y, &ep.inner.X)
	p.Z = ep.inner.Z
	p.T2d.Mul(&ep.inner.T, &constEDWARDS_D2)
}

func (p *affineNielsPoint) fromEdwards(ep *EdwardsPoint) {
	recip := ep.inner.Z
	recip.Invert()
	var x, y, xy field.FieldElement
	x.Mul(&ep.inner.X, &recip)
	y.Mul(&ep.inner.Y, &recip)
	xy.Mul(&x, &y)
	p.y_plus_x.Add(&y, &x)
	p.y_minus_x.Sub(&y, &x)
	p.xy2d.Mul(&xy, &constEDWARDS_D2)
}

func (p *completedPoint) double(pp *projectivePoint) {
	XX := pp.X
	XX.Square()
	YY := pp.Y
	YY.Square()
	ZZ2 := pp.Z
	ZZ2.Square2()
	var X_plus_Y field.FieldElement
	X_plus_Y.Add(&pp.X, &pp.Y)
	X_plus_Y_sq := X_plus_Y
	X_plus_Y_sq.Square()

	p.Y.Add(&YY, &XX)
	p.X.Sub(&X_plus_Y_sq, &p.Y)
	p.Z.Sub(&YY, &XX)
	p.T.Sub(&ZZ2, &p.Z)
}

func (p *completedPoint) addEdwardsProjectiveNiels(a *EdwardsPoint, b *projectiveNielsPoint) {
	var Y_plus_X, Y_minus_X, PP, MM, TT2d, ZZ, ZZ2 field.FieldElement
	Y_plus_X.Add(&a.inner.Y, &a.inner.X)
	Y_minus_X.Sub(&a.inner.Y, &a.inner.X)
	PP.Mul(&Y_plus_X, &b.Y_plus_X)
	MM.Mul(&Y_minus_X, &b.Y_minus_X)
	TT2d.Mul(&a.inner.T, &b.T2d)
	ZZ.Mul(&a.inner.Z, &b.Z)
	ZZ2.Add(&ZZ, &ZZ)

	p.X.Sub(&PP, &MM)
	p.Y.Add(&PP, &MM)
	p.Z.Add(&ZZ2, &TT2d)
	p.T.Sub(&ZZ2, &TT2d)
}

func (p *completedPoint) addCompletedProjectiveNiels(a *completedPoint, b *projectiveNielsPoint) {
	var aTmp EdwardsPoint
	aTmp.fromCompleted(a)
	p.addEdwardsProjectiveNiels(&aTmp, b)
}

func (p *completedPoint) subEdwardsProjectiveNiels(a *EdwardsPoint, b *projectiveNielsPoint) {
	var Y_plus_X, Y_minus_X, PM, MP, TT2d, ZZ, ZZ2 field.FieldElement
	Y_plus_X.Add(&a.inner.Y, &a.inner.X)
	Y_minus_X.Sub(&a.inner.Y, &a.inner.X)
	PM.Mul(&Y_plus_X, &b.Y_minus_X)
	MP.Mul(&Y_minus_X, &b.Y_plus_X)
	TT2d.Mul(&a.inner.T, &b.T2d)
	ZZ.Mul(&a.inner.Z, &b.Z)
	ZZ2.Add(&ZZ, &ZZ)

	p.X.Sub(&PM, &MP)
	p.Y.Add(&PM, &MP)
	p.Z.Sub(&ZZ2, &TT2d)
	p.T.Add(&ZZ2, &TT2d)
}

func (p *completedPoint) subCompletedProjectiveNiels(a *completedPoint, b *projectiveNielsPoint) {
	var aTmp EdwardsPoint
	aTmp.fromCompleted(a)
	p.subEdwardsProjectiveNiels(&aTmp, b)
}

func (p *completedPoint) addEdwardsAffineNiels(a *EdwardsPoint, b *affineNielsPoint) {
	var Y_plus_X, Y_minus_X, PP, MM, Txy2d, Z2 field.FieldElement
	Y_plus_X.Add(&a.inner.Y, &a.inner.X)
	Y_minus_X.Sub(&a.inner.Y, &a.inner.X)
	PP.Mul(&Y_plus_X, &b.y_plus_x)
	MM.Mul(&Y_minus_X, &b.y_minus_x)
	Txy2d.Mul(&a.inner.T, &b.xy2d)
	Z2.Add(&a.inner.Z, &a.inner.Z)

	p.X.Sub(&PP, &MM)
	p.Y.Add(&PP, &MM)
	p.Z.Add(&Z2, &Txy2d)
	p.T.Sub(&Z2, &Txy2d)
}

func (p *completedPoint) addCompletedAffineNiels(a *completedPoint, b *affineNielsPoint) {
	var aTmp EdwardsPoint
	aTmp.fromCompleted(a)
	p.addEdwardsAffineNiels(&aTmp, b)
}

func (p *completedPoint) subEdwardsAffineNiels(a *EdwardsPoint, b *affineNielsPoint) {
	var Y_plus_X, Y_minus_X, PM, MP, Txy2d, Z2 field.FieldElement
	Y_plus_X.Add(&a.inner.Y, &a.inner.X)
	Y_minus_X.Sub(&a.inner.Y, &a.inner.X)
	PM.Mul(&Y_plus_X, &b.y_minus_x)
	MP.Mul(&Y_minus_X, &b.y_plus_x)
	Txy2d.Mul(&a.inner.T, &b.xy2d)
	Z2.Add(&a.inner.Z, &a.inner.Z)

	p.X.Sub(&PM, &MP)
	p.Y.Add(&PM, &MP)
	p.Z.Sub(&Z2, &Txy2d)
	p.T.Add(&Z2, &Txy2d)
}

func (p *completedPoint) subCompletedAffineNiels(a *completedPoint, b *affineNielsPoint) {
	var aTmp EdwardsPoint
	aTmp.fromCompleted(a)
	p.subEdwardsAffineNiels(&aTmp, b)
}

func (p *projectiveNielsPoint) neg() {
	p.Y_plus_X, p.Y_minus_X = p.Y_minus_X, p.Y_plus_X
	p.T2d.Neg()
}

func (p *affineNielsPoint) neg() {
	p.y_plus_x, p.y_minus_x = p.y_minus_x, p.y_plus_x
	p.xy2d.Neg()
}

func (p *projectiveNielsPoint) conditionalNegate(choice int) {
	pNeg := *p
	pNeg.neg()

	p.conditionalAssign(&pNeg, choice)
}

func (p *affineNielsPoint) conditionalNegate(choice int) {
	pNeg := *p
	pNeg.neg()

	p.conditionalAssign(&pNeg, choice)
}
