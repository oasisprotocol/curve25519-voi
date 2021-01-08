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

import (
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"github.com/oasisprotocol/curve25519-voi/internal/field"
	"github.com/oasisprotocol/curve25519-voi/internal/subtle"
)

var errNotValidYCoordinate = fmt.Errorf("curve/edwards: not a valid y-coordinate")

// CompressedEdwardsY represents a curve point by the y-coordinate and
// the sign of x.
type CompressedEdwardsY [CompressedPointSize]byte

// FromBytes constructs a compressed Edwards point from a byte representation.
func (p *CompressedEdwardsY) FromBytes(in []byte) error {
	if len(in) != CompressedPointSize {
		return fmt.Errorf("curve/edwards: unexpected input size")
	}

	copy(p[:], in)

	return nil
}

// FromEdwardsPoint compresses an Edwards point.
func (p *CompressedEdwardsY) FromEdwardsPoint(point *EdwardsPoint) {
	var x, y field.FieldElement
	recip := point.inner.Z
	recip.Invert()
	x.Mul(&point.inner.X, &recip)
	y.Mul(&point.inner.Y, &recip)

	_ = y.ToBytes(p[:])
	p[31] ^= byte(x.IsNegative()) << 7
}

// Equal returns 1 iff the compresed points are equal, 0 otherwise.
// This function will execute in constant-time.
func (p *CompressedEdwardsY) Equal(other *CompressedEdwardsY) int {
	return subtle.ConstantTimeCompareBytes(p[:], other[:])
}

// Identity sets the compressed point to the identity element.
func (p *CompressedEdwardsY) Identity() {
	*p = [CompressedPointSize]byte{
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
}

// EdwardsPoint represents a point on the Edwards form of Curve25519.
type EdwardsPoint struct {
	inner edwardsPointInner
}

type edwardsPointInner struct {
	X field.FieldElement
	Y field.FieldElement
	Z field.FieldElement
	T field.FieldElement
}

// Identity sets the Edwards point to the identity element.
func (p *EdwardsPoint) Identity() {
	p.inner.X.Zero()
	p.inner.Y.One()
	p.inner.Z.One()
	p.inner.T.Zero()
}

// FromCompressedY attempts to decompress a CompressedEdwardsY into an
// EdwardsPoint.
func (p *EdwardsPoint) FromCompressedY(compressedY *CompressedEdwardsY) error {
	var Y, u, v, X field.FieldElement
	if err := Y.FromBytes(compressedY[:]); err != nil {
		return err
	}
	Z := field.One()
	YY := Y
	YY.Square()
	u.Sub(&YY, &Z)              // u = y^2 - 1
	v.Mul(&YY, &constEDWARDS_D) // v = dy^2 + 1
	v.Add(&v, &Z)
	isValidYCoord := X.SqrtRatioI(&u, &v)

	if isValidYCoord != 1 {
		return errNotValidYCoordinate
	}

	// field.FieldElement.SqrtRatioI always returns the nonnegative square root,
	// so we negate according to the supplied sign bit.
	compressedSignBit := int(compressedY[31] >> 7)
	X.ConditionalNegate(compressedSignBit)

	p.inner.X = X
	p.inner.Y = Y
	p.inner.Z = Z
	p.inner.T.Mul(&X, &Y)

	return nil
}

// ConditionalSelect sets the point to a iff choice == 0 and b iff
// choice == 1.
func (p *EdwardsPoint) ConditionalSelect(a, b *EdwardsPoint, choice int) {
	p.inner.X.ConditionalSelect(&a.inner.X, &b.inner.X, choice)
	p.inner.Y.ConditionalSelect(&a.inner.Y, &b.inner.Y, choice)
	p.inner.Z.ConditionalSelect(&a.inner.Z, &b.inner.Z, choice)
	p.inner.T.ConditionalSelect(&a.inner.T, &b.inner.T, choice)
}

// Equal returns 1 iff the points are equal, 0 otherwise. This function
// will execute in constant-time.
func (p *EdwardsPoint) Equal(other *EdwardsPoint) int {
	// We would like to check that the point (X/Z, Y/Z) is equal to
	// the point (X'/Z', Y'/Z') without converting into affine
	// coordinates (x, y) and (x', y'), which requires two inversions.
	// We have that X = xZ and X' = x'Z'. Thus, x = x' is equivalent to
	// (xZ)Z' = (x'Z')Z, and similarly for the y-coordinate.
	var sXoZ, oXsZ, sYoZ, oYsZ field.FieldElement
	sXoZ.Mul(&p.inner.X, &other.inner.Z)
	oXsZ.Mul(&other.inner.X, &p.inner.Z)
	sYoZ.Mul(&p.inner.Y, &other.inner.Z)
	oYsZ.Mul(&other.inner.Y, &p.inner.Z)

	return sXoZ.Equal(&oXsZ) & sYoZ.Equal(&oYsZ)
}

// double adds the point to itself.
func (p *EdwardsPoint) double() {
	var pProjective projectivePoint
	pProjective.fromEdwards(p)

	var sum completedPoint
	sum.double(&pProjective)
	p.fromCompleted(&sum)
}

// Add computes `a + b`.
func (p *EdwardsPoint) Add(a, b *EdwardsPoint) {
	var bPNiels projectiveNielsPoint
	bPNiels.fromEdwards(b)

	var sum completedPoint
	sum.addEdwardsProjectiveNiels(a, &bPNiels)
	p.fromCompleted(&sum)
}

// Sub computes `a - b`.
func (p *EdwardsPoint) Sub(a, b *EdwardsPoint) {
	var bPNiels projectiveNielsPoint
	bPNiels.fromEdwards(b)

	var diff completedPoint
	diff.subEdwardsProjectiveNiels(a, &bPNiels)
	p.fromCompleted(&diff)
}

// Sum sets the point to the sum of a slice of points.
func (p *EdwardsPoint) Sum(values []*EdwardsPoint) {
	p.Identity()
	for _, v := range values {
		p.Add(p, v)
	}
}

// Neg computes `-P`.
func (p *EdwardsPoint) Neg() {
	p.inner.X.Neg()
	p.inner.T.Neg()
}

// MultiscalarMul computes `scalars[0] * points[0] + ... scalars[n] * points[n]`
// in constant-time.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *EdwardsPoint) MultiscalarMul(scalars []*scalar.Scalar, points []*EdwardsPoint) {
	if len(scalars) != len(points) {
		panic("curve/edwards: len(scalars) != len(points")
	}

	// There is only one constant-time implementation of this, so use it.
	p.multiscalarMulStraus(scalars, points)
}

// MultiscalarMulVartime computes `scalars[0] * points[0] + ... scalars[n] * points[n]`
// in variable-time.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *EdwardsPoint) MultiscalarMulVartime(scalars []*scalar.Scalar, points []*EdwardsPoint) {
	size := len(scalars)
	if size != len(points) {
		panic("curve/edwards: len(scalars) != len(points")
	}

	p.multiscalarMulStrausVartime(scalars, points)
	if size < 190 {
		p.multiscalarMulStrausVartime(scalars, points)
	} else {
		p.multiscalarMulPippengerVartime(scalars, points)
	}
}

// MulByCofactor computes `[8]P`.
func (p *EdwardsPoint) MulByCofactor() {
	p.mulByPow2(3)
}

// IsSmallOrder returns true if p is in the torsion subgroup `E[8]`.
func (p *EdwardsPoint) IsSmallOrder() bool {
	check := *p
	check.MulByCofactor()
	return check.IsIdentity()
}

// IsTorsionFree returns true if p is "torsion-free", i.e., is contained
// in the prime-order subgroup.
func (p *EdwardsPoint) IsTorsionFree() bool {
	var check EdwardsPoint
	check.Mul(p, &BASEPOINT_ORDER)
	return check.IsIdentity()
}

// IsIdentity returns true iff the point is equivalent to the identity element
// of the curve.
func (p *EdwardsPoint) IsIdentity() bool {
	var identity EdwardsPoint
	identity.Identity()
	return p.Equal(&identity) == 1
}

func (p *EdwardsPoint) debugIsValid() bool {
	var pProjective projectivePoint
	pProjective.fromEdwards(p)
	pointOnCurve := pProjective.debugIsValid()

	var XY, ZT field.FieldElement
	XY.Mul(&p.inner.X, &p.inner.Y)
	ZT.Mul(&p.inner.Z, &p.inner.T)
	onSegreImage := XY.Equal(&ZT) == 1

	return pointOnCurve && onSegreImage
}

// mulByPow2 computes `[2^k]P` by successive doublings.  Requires `k > 0`.
func (p *EdwardsPoint) mulByPow2(k uint) {
	if k == 0 {
		panic("curve/edwards: k out of bounds")
	}

	var r completedPoint
	var s projectivePoint
	s.fromEdwards(p)
	for i := uint(0); i < k-1; i++ {
		r.double(&s)
		s.fromCompleted(&r)
	}
	// Unroll last iteration so we can directly convert back to an EdwardsPoint.
	r.double(&s)
	p.fromCompleted(&r)
}

// EdwardsBasepointTable defines a precomputed table of multiples of a
// basepoint, for accelerating fixed-based scalar multiplication.
type EdwardsBasepointTable [32]affineNielsPointLookupTable

// Mul constructs a point from a scalar by computing the multiple aB
// of this basepoint (B).
func (tbl *EdwardsBasepointTable) Mul(scalar *scalar.Scalar) EdwardsPoint {
	a := scalar.ToRadix16()

	var p EdwardsPoint
	p.Identity()

	var sum completedPoint
	for i := 1; i < 64; i = i + 2 {
		aPt := tbl[i/2].lookup(a[i])
		sum.addEdwardsAffineNiels(&p, &aPt)
		p.fromCompleted(&sum)
	}

	p.mulByPow2(4)

	for i := 0; i < 64; i = i + 2 {
		aPt := tbl[i/2].lookup(a[i])
		sum.addEdwardsAffineNiels(&p, &aPt)
		p.fromCompleted(&sum)
	}

	return p
}

// Basepoint returns the basepoint of the table.
func (tbl *EdwardsBasepointTable) Basepoint() EdwardsPoint {
	// tbl[0].lookup(1) = 1*(16^2)^0*B
	// but as an `affineNielsPoint`, so add identity to convert to extended.
	var ep EdwardsPoint
	ep.Identity()
	aPt := tbl[0].lookup(1)
	var sum completedPoint
	sum.addEdwardsAffineNiels(&ep, &aPt)
	ep.fromCompleted(&sum)

	return ep
}

// NewEdwardsBasepointTable creates a table of precomputed multiples of
// `basepoint`.
func NewEdwardsBasepointTable(basepoint *EdwardsPoint) EdwardsBasepointTable {
	var table EdwardsBasepointTable
	p := *basepoint
	for i := 0; i < 32; i++ {
		table[i] = newAffineNielsPointLookupTable(&p)
		p.mulByPow2(8)
	}

	return table
}

// Omitted:
//  * VartimeEdwardsPrecomputation
