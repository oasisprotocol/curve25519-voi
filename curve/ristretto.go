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
	"crypto/rand"
	"fmt"
	"io"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"github.com/oasisprotocol/curve25519-voi/internal/field"
	"github.com/oasisprotocol/curve25519-voi/internal/subtle"
)

// CompressedRistretto represents a Ristretto point in wire format.
type CompressedRistretto [CompressedPointSize]byte

// FromBytes constructs a compressed Ristretto point from a byte representation.
func (p *CompressedRistretto) FromBytes(in []byte) error {
	if len(in) != CompressedPointSize {
		return fmt.Errorf("curve/ristretto: unexpected input size")
	}

	copy(p[:], in)

	return nil
}

// FromRistrettoPoint compresses a Ristretto point into a CompressedRistretto.
func (p *CompressedRistretto) FromRistrettoPoint(ristrettoPoint *RistrettoPoint) {
	ip := &ristrettoPoint.inner // Make this look less ugly.
	X := ip.inner.X
	Y := ip.inner.Y
	Z := ip.inner.Z
	T := ip.inner.T

	var u1, u2, tmp field.FieldElement
	u1.Add(&Z, &Y)
	tmp.Sub(&Z, &Y)
	u1.Mul(&u1, &tmp)
	u2.Mul(&X, &Y)

	// Ignore return value since this is always square.
	invsqrt := u2
	invsqrt.Square()
	invsqrt.Mul(&u1, &invsqrt)
	_ = invsqrt.InvSqrt()
	var i1, i2, zInv field.FieldElement
	i1.Mul(&invsqrt, &u1)
	i2.Mul(&invsqrt, &u2)
	zInv.Mul(&i2, &T)
	zInv.Mul(&i1, &zInv)
	denInv := i2

	var iX, iY, enchantedDenominator field.FieldElement
	iX.Mul(&X, &field.SQRT_M1)
	iY.Mul(&Y, &field.SQRT_M1)
	enchantedDenominator.Mul(&i1, &field.INVSQRT_A_MINUS_D)

	tmp.Mul(&T, &zInv)
	rotate := tmp.IsNegative()

	X.ConditionalAssign(&iY, rotate)
	Y.ConditionalAssign(&iX, rotate)
	denInv.ConditionalAssign(&enchantedDenominator, rotate)

	tmp.Mul(&X, &zInv)
	Y.ConditionalNegate(tmp.IsNegative())

	var s field.FieldElement
	s.Sub(&Z, &Y)
	s.Mul(&denInv, &s)

	sIsNegative := s.IsNegative()
	s.ConditionalNegate(sIsNegative)

	_ = s.ToBytes(p[:])
}

// Equal returns 1 iff the compressed points are equal, 0 otherwise.
// This function will execute in constant-time.
func (p *CompressedRistretto) Equal(other *CompressedRistretto) int {
	return subtle.ConstantTimeCompareBytes(p[:], other[:])
}

// Identity sets the compressed point to the identity element.
func (p *CompressedRistretto) Identity() {
	for i := range p {
		p[i] = 0
	}
}

// RistrettoPoint represents a point in the Ristretto group for Curve25519.
type RistrettoPoint struct {
	inner EdwardsPoint
}

// Identity sets the Ristretto point to the identity element.
func (p *RistrettoPoint) Identity() {
	p.inner.Identity()
}

// FromCompressed attempts to decompress a CompressedRistretto into a
// RistrettoPoint.
func (p *RistrettoPoint) FromCompressed(compressed *CompressedRistretto) error {
	// Step 1. Check s for validity:
	// 1.a) s must be 32 bytes (we get this from the type system)
	// 1.b) s < p
	// 1.c) s is nonnegative
	//
	// Our decoding routine ignores the high bit, so the only
	// possible failure for 1.b) is if someone encodes s in 0..18
	// as s+p in 2^255-19..2^255-1.  We can check this by
	// converting back to bytes, and checking that we get the
	// original input, since our encoding routine is canonical.

	var (
		s           field.FieldElement
		sBytesCheck [field.FieldElementSize]byte
	)
	if err := s.FromBytes(compressed[:]); err != nil {
		return fmt.Errorf("curve/ristretto: failed to deserialize s: %w", err)
	}
	_ = s.ToBytes(sBytesCheck[:])
	sEncodingIsCanonical := subtle.ConstantTimeCompareBytes(compressed[:], sBytesCheck[:])
	sIsNegative := s.IsNegative()

	if sEncodingIsCanonical != 1 || sIsNegative == 1 {
		return fmt.Errorf("curve/ristretto: s is not a canonical encoding")
	}

	// Step 2. Compute (X:Y:Z:T).
	var (
		one    = field.One()
		ss     = s
		u1, u2 field.FieldElement
	)
	ss.Square()
	u1.Sub(&one, &ss) // 1 + as^2
	u2.Add(&one, &ss) // 1 - as^2 where a = -1
	u1Sqr, u2Sqr := u1, u2
	u1Sqr.Square()
	u2Sqr.Square()

	// v == ad(1+as^2)^2 - (1-as^2)^2 where d=-121665/121666
	v := constEDWARDS_D
	v.Neg()
	v.Mul(&v, &u1Sqr)
	v.Sub(&v, &u2Sqr)

	var I field.FieldElement
	I.Mul(&v, &u2Sqr)
	ok := I.InvSqrt() // 1/sqrt(v*u_2^2)

	_ = ok
	var Dx, Dy field.FieldElement
	Dx.Mul(&I, &u2) // 1/sqrt(v)
	Dy.Mul(&Dx, &v)
	Dy.Mul(&I, &Dy) // 1/u2

	// x == | 2s/sqrt(v) | == + sqrt(4s^2/(ad(1+as^2)^2 - (1-as^2)^2))
	var x field.FieldElement
	x.Add(&s, &s)
	x.Mul(&x, &Dx)
	x.ConditionalNegate(x.IsNegative())

	// y == (1-as^2)/(1+as^2)
	var y field.FieldElement
	y.Mul(&u1, &Dy)

	// t == ((1+as^2) sqrt(4s^2/(ad(1+as^2)^2 - (1-as^2)^@)))/(1-as^2)
	var t field.FieldElement
	t.Mul(&x, &y)

	if ok != 1 || t.IsNegative() == 1 || y.IsZero() == 1 {
		return fmt.Errorf("curve/ristretto: s is is not a valid point")
	}

	p.inner = EdwardsPoint{edwardsPointInner{x, y, one, t}}

	return nil
}

// Random sets the point to one chosen uniformly at random using entropy
// from the user-provided io.Reader.  If rng is nil, the runtime library's
// entropy source will be used.
func (p *RistrettoPoint) Random(rng io.Reader) error {
	var pointBytes [RistrettoUniformSize]byte

	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, pointBytes[:]); err != nil {
		return fmt.Errorf("curve/ristretto: failed to read entropy: %w", err)
	}

	return p.FromUniformBytes(pointBytes[:])
}

// FromUniformBytes sets the point to that from 64 bytes of random
// data.  If the input bytes are uniformly distributed, the resulting point
// will be uniformly distributed over the group, and its discrete log with
// respect to other points should be unknown.
func (p *RistrettoPoint) FromUniformBytes(in []byte) error {
	if len(in) != RistrettoUniformSize {
		return fmt.Errorf("curve/ristretto: unexpected input size")
	}
	var (
		r_1, r_2 field.FieldElement
		R_1, R_2 RistrettoPoint
	)
	if err := r_1.FromBytes(in[:32]); err != nil {
		return fmt.Errorf("curve/ristretto: failed to deserialize r_1: %w", err)
	}
	R_1.elligatorRistrettoFlavor(&r_1)
	if err := r_2.FromBytes(in[32:]); err != nil {
		return fmt.Errorf("curve/ristretto: failed to deserialize r_2: %w", err)
	}
	R_2.elligatorRistrettoFlavor(&r_2)

	// Applying Elligator twice and adding the results ensures a
	// uniform distribution.
	p.Add(&R_1, &R_2)

	return nil
}

// ConditionalSelect sets the point to a iff choice == 0 and b iff
// choice == 1.
func (p *RistrettoPoint) ConditionalSelect(a, b *RistrettoPoint, choice int) {
	p.inner.ConditionalSelect(&a.inner, &b.inner, choice)
}

// Equal returns 1 iff the points are equal, 0 otherwise. This function
// will execute in constant-time.
func (p *RistrettoPoint) Equal(other *RistrettoPoint) int {
	pI, oI := &p.inner, &other.inner // Make this look less ugly.
	var X1Y2, Y1X2, X1X2, Y1Y2 field.FieldElement
	X1Y2.Mul(&pI.inner.X, &oI.inner.Y)
	Y1X2.Mul(&pI.inner.Y, &oI.inner.X)
	X1X2.Mul(&pI.inner.X, &oI.inner.X)
	Y1Y2.Mul(&pI.inner.Y, &oI.inner.Y)

	return X1Y2.Equal(&Y1X2) | X1X2.Equal(&Y1Y2)
}

// Add computes `a + b`.
func (p *RistrettoPoint) Add(a, b *RistrettoPoint) {
	p.inner.Add(&a.inner, &b.inner)
}

// Sub computes `a - b`.
func (p *RistrettoPoint) Sub(a, b *RistrettoPoint) {
	p.inner.Sub(&a.inner, &b.inner)
}

// Sum sets the point to the sum of a slice of points.
func (p *RistrettoPoint) Sum(values []*RistrettoPoint) {
	p.Identity()
	for _, v := range values {
		p.Add(p, v)
	}
}

// Neg computes `-P`.
func (p *RistrettoPoint) Neg() {
	p.inner.Neg()
}

// Mul computes `point * scalar` in constant-time (variable-base scalar
// multiplication).
func (p *RistrettoPoint) Mul(point *RistrettoPoint, scalar *scalar.Scalar) {
	p.inner.Mul(&point.inner, scalar)
}

// MultiscalarMul computes `scalars[0] * points[0] + ... scalars[n] * points[n]`
// in constant-time.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *RistrettoPoint) MultiscalarMul(scalars []*scalar.Scalar, points []*RistrettoPoint) {
	edwardsPoints := make([]*EdwardsPoint, 0, len(points))
	for _, point := range points {
		edwardsPoints = append(edwardsPoints, &point.inner)
	}

	p.inner.MultiscalarMul(scalars, edwardsPoints)
}

// MultiscalarMulVartime computes `scalars[0] * points[0] + ... scalars[n] * points[n]`
// in variable-time.
//
// WARNING: This function will panic if `len(scalars) != len(points)`.
func (p *RistrettoPoint) MultiscalarMulVartime(scalars []*scalar.Scalar, points []*RistrettoPoint) {
	edwardsPoints := make([]*EdwardsPoint, 0, len(points))
	for _, point := range points {
		edwardsPoints = append(edwardsPoints, &point.inner)
	}

	p.inner.MultiscalarMulVartime(scalars, edwardsPoints)
}

// DoubleScalarMulBasepointVartime computes (aA + bB) in variable time,
// where B is the Ristretto basepoint.
func (p *RistrettoPoint) DoubleScalarMulBasepointVartime(a *scalar.Scalar, A *RistrettoPoint, b *scalar.Scalar) {
	p.inner.DoubleScalarMulBasepointVartime(a, &A.inner, b)
}

func (p *RistrettoPoint) elligatorRistrettoFlavor(r_0 *field.FieldElement) {
	c := constMINUS_ONE
	one := field.One()

	r := *r_0
	r.Square()
	r.Mul(&field.SQRT_M1, &r)
	var N_s field.FieldElement
	N_s.Add(&r, &one)
	N_s.Mul(&N_s, &constONE_MINUS_EDWARDS_D_SQUARED)
	var D, tmp field.FieldElement
	tmp.Add(&r, &constEDWARDS_D)
	D.Mul(&constEDWARDS_D, &r)
	D.Sub(&c, &D)
	D.Mul(&D, &tmp)

	var s, s_prime field.FieldElement
	Ns_D_is_sq := s.SqrtRatioI(&N_s, &D)
	s_prime.Mul(&s, r_0)
	s_prime_is_pos := s_prime.IsNegative() ^ 1
	s_prime.ConditionalNegate(s_prime_is_pos)

	Ns_D_is_not_sq := Ns_D_is_sq ^ 1

	s.ConditionalAssign(&s_prime, Ns_D_is_not_sq)
	c.ConditionalAssign(&r, Ns_D_is_not_sq)

	var N_t field.FieldElement
	N_t.Sub(&r, &one)
	N_t.Mul(&c, &N_t)
	N_t.Mul(&N_t, &constEDWARDS_D_MINUS_ONE_SQUARED)
	N_t.Sub(&N_t, &D)

	s_sq := s
	s_sq.Square()

	var cp completedPoint
	cp.X.Add(&s, &s)
	cp.X.Mul(&cp.X, &D)
	cp.Z.Mul(&N_t, &constSQRT_AD_MINUS_ONE)
	cp.Y.Sub(&one, &s_sq)
	cp.T.Add(&one, &s_sq)

	// The conversion from W_i is exactly the conversion from P1xP1.
	p.inner.fromCompleted(&cp)
}

func (p *RistrettoPoint) coset4() [4]EdwardsPoint {
	var ret [4]EdwardsPoint

	ret[0] = p.inner
	ret[1].Add(&p.inner, &EIGHT_TORSION[2])
	ret[2].Add(&p.inner, &EIGHT_TORSION[4])
	ret[3].Add(&p.inner, &EIGHT_TORSION[6])

	return ret
}

// RistrettoBasepointTable defines a precomputed table of multiples of a
// basepoint, for accelerating fixed-based scalar multiplication.
type RistrettoBasepointTable struct {
	inner EdwardsBasepointTable
}

// Mul constructs a point from a scalar by computing the multiple aB
// of this basepoint (B).
func (tbl *RistrettoBasepointTable) Mul(scalar *scalar.Scalar) RistrettoPoint {
	return RistrettoPoint{
		inner: tbl.inner.Mul(scalar),
	}
}

// Basepoint returns the basepoint of the table.
func (tbl *RistrettoBasepointTable) Basepoint() RistrettoPoint {
	return RistrettoPoint{
		inner: tbl.inner.Basepoint(),
	}
}

// NewRistrettoBasepointTable creates a table of precomputed multiples of
// `basepoint`.
func NewRistrettoBasepointTable(basepoint *RistrettoPoint) RistrettoBasepointTable {
	return RistrettoBasepointTable{
		inner: NewEdwardsBasepointTable(&basepoint.inner),
	}
}

// Omitted:
//  * DoubleAndCompressBatch
//  * HashFromBytes
//  * FromHash
//  * VartimeRistrettoPrecomputation
