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
	"bytes"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"github.com/oasisprotocol/curve25519-voi/internal/field"
	"github.com/oasisprotocol/curve25519-voi/internal/subtle"
)

var (
	errNotValidYCoordinate = fmt.Errorf("curve/edwards: not a valid y-coordinate")

	noncanonicalSignBits = []CompressedEdwardsY{
		// y = 1
		{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		},
		// y = 2^255-18
		{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
	}
)

// CompressedEdwardsY represents a curve point by the y-coordinate and
// the sign of x.
type CompressedEdwardsY [CompressedPointSize]byte

// SetBytes constructs a compressed Edwards point from a byte representation.
func (p *CompressedEdwardsY) SetBytes(in []byte) (*CompressedEdwardsY, error) {
	if len(in) != CompressedPointSize {
		return nil, fmt.Errorf("curve/edwards: unexpected input size")
	}

	copy(p[:], in)

	return p, nil
}

// SetEdwardsPoint compresses an Edwards point.
func (p *CompressedEdwardsY) SetEdwardsPoint(point *EdwardsPoint) *CompressedEdwardsY {
	var x, y, recip field.FieldElement
	recip.Invert(&point.inner.Z)
	x.Mul(&point.inner.X, &recip)
	y.Mul(&point.inner.Y, &recip)

	_ = y.ToBytes(p[:])
	p[31] ^= byte(x.IsNegative()) << 7

	return p
}

// Equal returns 1 iff the compresed points are equal, 0 otherwise.
// This function will execute in constant-time.
func (p *CompressedEdwardsY) Equal(other *CompressedEdwardsY) int {
	return subtle.ConstantTimeCompareBytes(p[:], other[:])
}

// Identity sets the compressed point to the identity element.
func (p *CompressedEdwardsY) Identity() *CompressedEdwardsY {
	*p = [CompressedPointSize]byte{
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	return p
}

// IsCanonical returns true if p is a canonical encoding in variable-time.
func (p *CompressedEdwardsY) IsCanonical() bool {
	// Check that Y is canonical, using the succeed-fast algorithm from
	// the "Taming the many EdDSAs" paper.
	yCanonical := func() bool {
		if p[0] < 237 {
			return true
		}
		for i := 1; i < 31; i++ {
			if p[i] != 255 {
				return true
			}
		}
		return (p[31] | 128) != 255
	}()
	if !yCanonical {
		return false
	}

	// Test for the two cases with a canonically encoded y with a
	// noncanonical sign bit.  Since it's just two cases, and this
	// routine is explicitly variable time, just do variable-time
	// byte comparisons.
	for _, invalidEncoding := range noncanonicalSignBits {
		if bytes.Equal(p[:], invalidEncoding[:]) {
			return false
		}
	}

	return true
}

// NewCompressedEdwardsY constructs a new compressed Edwards point,
// set to the identity element.
func NewCompressedEdwardsY() *CompressedEdwardsY {
	var p CompressedEdwardsY
	return p.Identity()
}

// NewCompressedEdwardsYFromBytes constructs a new compressed Edwards point,
// set to provided byte representation.
func NewCompressedEdwardsYFromBytes(in []byte) (*CompressedEdwardsY, error) {
	var p CompressedEdwardsY
	return p.SetBytes(in)
}

// EdwardsPoint represents a point on the Edwards form of Curve25519.
//
// The default value is NOT valid and MUST only be used as a receiver.
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
func (p *EdwardsPoint) Identity() *EdwardsPoint {
	p.inner.X.Zero()
	p.inner.Y.One()
	p.inner.Z.One()
	p.inner.T.Zero()
	return p
}

// Set sets `p = t`, and returns p.
func (p *EdwardsPoint) Set(t *EdwardsPoint) *EdwardsPoint {
	p.inner.X.Set(&t.inner.X)
	p.inner.Y.Set(&t.inner.Y)
	p.inner.Z.Set(&t.inner.Z)
	p.inner.T.Set(&t.inner.T)
	return p
}

// SetCompressedY attempts to decompress a CompressedEdwardsY into an
// EdwardsPoint.
func (p *EdwardsPoint) SetCompressedY(compressedY *CompressedEdwardsY) (*EdwardsPoint, error) {
	var Y, Z, YY, u, v, X field.FieldElement
	if _, err := Y.SetBytes(compressedY[:]); err != nil {
		return nil, err
	}
	Z.One()
	YY.Square(&Y)
	u.Sub(&YY, &Z)              // u = y^2 - 1
	v.Mul(&YY, &constEDWARDS_D) // v = dy^2 + 1
	v.Add(&v, &Z)
	_, isValidYCoord := X.SqrtRatioI(&u, &v)

	if isValidYCoord != 1 {
		return nil, errNotValidYCoordinate
	}

	// field.FieldElement.SqrtRatioI always returns the nonnegative square root,
	// so we negate according to the supplied sign bit.
	compressedSignBit := int(compressedY[31] >> 7)
	X.ConditionalNegate(compressedSignBit)

	p.inner.X.Set(&X)
	p.inner.Y.Set(&Y)
	p.inner.Z.Set(&Z)
	p.inner.T.Mul(&X, &Y)

	return p, nil
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

// EqualCompresedY returns 1 iff the point is equal to the compressed
// point, 0 otherwise.  This function will execute in constant time.
func (p *EdwardsPoint) EqualCompressedY(other *CompressedEdwardsY) int {
	var pCompressed CompressedEdwardsY
	return other.Equal(pCompressed.SetEdwardsPoint(p))
}

// Add sets `p = a + b`, and returns p.
func (p *EdwardsPoint) Add(a, b *EdwardsPoint) *EdwardsPoint {
	var (
		bPNiels projectiveNielsPoint
		sum     completedPoint
	)
	return p.setCompleted(sum.AddEdwardsProjectiveNiels(a, bPNiels.SetEdwards(b)))
}

// Sub sets `p = a - b`, and returns p.
func (p *EdwardsPoint) Sub(a, b *EdwardsPoint) *EdwardsPoint {
	var (
		bPNiels projectiveNielsPoint
		diff    completedPoint
	)
	return p.setCompleted(diff.SubEdwardsProjectiveNiels(a, bPNiels.SetEdwards(b)))
}

// Sum sets p to the sum of values, and returns p.
func (p *EdwardsPoint) Sum(values []*EdwardsPoint) *EdwardsPoint {
	p.Identity()
	for _, v := range values {
		p.Add(p, v)
	}

	return p
}

// Neg sets `p = -t`, and returns p.
func (p *EdwardsPoint) Neg(t *EdwardsPoint) *EdwardsPoint {
	p.inner.X.Neg(&t.inner.X)
	p.inner.Y.Set(&t.inner.Y)
	p.inner.Z.Set(&t.inner.Z)
	p.inner.T.Neg(&t.inner.T)
	return p
}

// Mul sets `p = point * scalar` in constant-time (variable-base scalar
// multiplication), and returns p.
func (p *EdwardsPoint) Mul(point *EdwardsPoint, scalar *scalar.Scalar) *EdwardsPoint {
	return edwardsMul(p, point, scalar)
}

// DoubleScalarMulBasepointVartime sets `p = (aA + bB)` in variable time,
// where B is the Ed25519 basepoint, and returns p.
func (p *EdwardsPoint) DoubleScalarMulBasepointVartime(a *scalar.Scalar, A *EdwardsPoint, b *scalar.Scalar) *EdwardsPoint {
	return edwardsDoubleScalarMulBasepointVartime(p, a, A, b)
}

// MultiscalarMul sets `p = scalars[0] * points[0] + ... scalars[n] * points[n]`
// in constant-time, and returns p.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *EdwardsPoint) MultiscalarMul(scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	if len(scalars) != len(points) {
		panic("curve/edwards: len(scalars) != len(points)")
	}

	// There is only one constant-time implementation of this, so use it.
	return edwardsMultiscalarMulStraus(p, scalars, points)
}

// MultiscalarMulVartime sets `p = scalars[0] * points[0] + ... scalars[n] * points[n]`
// in variable-time, and returns p.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *EdwardsPoint) MultiscalarMulVartime(scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	size := len(scalars)
	if size != len(points) {
		panic("curve/edwards: len(scalars) != len(points)")
	}

	if size < 190 {
		return edwardsMultiscalarMulStrausVartime(p, scalars, points)
	} else {
		return edwardsMultiscalarMulPippengerVartime(p, scalars, points)
	}
}

// MulByCofactor sets `p = [8]t`, and returns p.
func (p *EdwardsPoint) MulByCofactor(t *EdwardsPoint) *EdwardsPoint {
	return p.mulByPow2(t, 3)
}

// IsSmallOrder returns true if p is in the torsion subgroup `E[8]`.
func (p *EdwardsPoint) IsSmallOrder() bool {
	var check EdwardsPoint
	return check.MulByCofactor(p).IsIdentity()
}

// IsTorsionFree returns true if p is "torsion-free", i.e., is contained
// in the prime-order subgroup.
func (p *EdwardsPoint) IsTorsionFree() bool {
	var check EdwardsPoint
	return check.Mul(p, BASEPOINT_ORDER).IsIdentity()
}

// IsIdentity returns true iff the point is equivalent to the identity element
// of the curve.
func (p *EdwardsPoint) IsIdentity() bool {
	var id EdwardsPoint
	return p.Equal(id.Identity()) == 1
}

func (p *EdwardsPoint) debugIsValid() bool {
	var pProjective projectivePoint
	pProjective.SetEdwards(p)
	pointOnCurve := pProjective.debugIsValid()

	var XY, ZT field.FieldElement
	XY.Mul(&p.inner.X, &p.inner.Y)
	ZT.Mul(&p.inner.Z, &p.inner.T)
	onSegreImage := XY.Equal(&ZT) == 1

	return pointOnCurve && onSegreImage
}

// double sets `p = 2t`, and returns p.
func (p *EdwardsPoint) double(t *EdwardsPoint) *EdwardsPoint {
	var (
		pProjective projectivePoint
		sum         completedPoint
	)
	return p.setCompleted(sum.Double(pProjective.SetEdwards(t)))
}

// mulByPow2 sets `p = [2^k]t` by successive doublings, and returns p.  Requires `k > 0`.
func (p *EdwardsPoint) mulByPow2(t *EdwardsPoint, k uint) *EdwardsPoint {
	if k == 0 {
		panic("curve/edwards: k out of bounds")
	}

	var (
		r completedPoint
		s projectivePoint
	)
	s.SetEdwards(t)
	for i := uint(0); i < k-1; i++ {
		s.SetCompleted(r.Double(&s))
	}
	// Unroll last iteration so we can directly convert back to an EdwardsPoint.
	return p.setCompleted(r.Double(&s))
}

// NewEdwardsPoint constructs a new Edwards point set to the identity element.
func NewEdwardsPoint() *EdwardsPoint {
	var p EdwardsPoint
	return p.Identity()
}

// EdwardsBasepointTable defines a precomputed table of multiples of a
// basepoint, for accelerating fixed-based scalar multiplication.
type EdwardsBasepointTable struct {
	// TODO/perf: Interface unboxing causes an allocation, but this is
	// the cleanest way to do this.  Since it's only one, and it's small
	// live with it for now.
	inner edwardsBasepointTableImpl
}

type edwardsBasepointTableImpl interface {
	Basepoint() EdwardsPoint
	Mul(scalar *scalar.Scalar) EdwardsPoint
}

// Mul constructs a point from a scalar by computing the multiple aB
// of this basepoint (B).
//
// Note: This function breaks from convention and does not return a pointer
// because Go's escape analysis sucks.
func (tbl *EdwardsBasepointTable) Mul(scalar *scalar.Scalar) EdwardsPoint {
	return tbl.inner.Mul(scalar)
}

// Basepoint returns the basepoint of the table.
//
// Note: This function breaks from convention and does not return a pointer
// because Go's escape analysis sucks.
func (tbl *EdwardsBasepointTable) Basepoint() EdwardsPoint {
	return tbl.inner.Basepoint()
}

// NewEdwardsBasepointTable creates a table of precomputed multiples of
// `basepoint`.
func NewEdwardsBasepointTable(basepoint *EdwardsPoint) *EdwardsBasepointTable {
	return &EdwardsBasepointTable{
		inner: newEdwardsBasepointTable(basepoint),
	}
}

// Omitted:
//  * VartimeEdwardsPrecomputation
