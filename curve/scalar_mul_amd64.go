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

package curve

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

// EdwardsBasepointTable defines a precomputed table of multiples of a
// basepoint, for accelerating fixed-based scalar multiplication.
type EdwardsBasepointTable struct {
	inner       *edwardsBasepointTableGeneric
	innerVector *edwardsBasepointTableVector
}

// Mul constructs a point from a scalar by computing the multiple aB
// of this basepoint (B).
//
// Note: This function breaks from convention and does not return a pointer
// because Go's escape analysis sucks.
func (tbl *EdwardsBasepointTable) Mul(scalar *scalar.Scalar) EdwardsPoint {
	if tbl.innerVector != nil {
		return tbl.innerVector.Mul(scalar)
	}
	return tbl.inner.Mul(scalar)
}

// Basepoint returns the basepoint of the table.
//
// Note: This function breaks from convention and does not return a pointer
// because Go's escape analysis sucks.
func (tbl *EdwardsBasepointTable) Basepoint() EdwardsPoint {
	if tbl.innerVector != nil {
		return tbl.innerVector.Basepoint()
	}
	return tbl.inner.Basepoint()
}

// NewEdwardsBasepointTable creates a table of precomputed multiples of
// `basepoint`.
func NewEdwardsBasepointTable(basepoint *EdwardsPoint) *EdwardsBasepointTable {
	if supportsVectorizedEdwards {
		return &EdwardsBasepointTable{
			innerVector: newEdwardsBasepointTableVector(basepoint),
		}
	}
	return &EdwardsBasepointTable{
		inner: newEdwardsBasepointTableGeneric(basepoint),
	}
}

func edwardsMul(out, point *EdwardsPoint, scalar *scalar.Scalar) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsMulVector(out, point, scalar)
	default:
		return edwardsMulGeneric(out, point, scalar)
	}
}

func edwardsDoubleScalarMulBasepointVartime(out *EdwardsPoint, a *scalar.Scalar, A *EdwardsPoint, b *scalar.Scalar) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsDoubleScalarMulBasepointVartimeVector(out, a, A, b)
	default:
		return edwardsDoubleScalarMulBasepointVartimeGeneric(out, a, A, b)
	}
}

func edwardsMulAbglsvPorninVartime(out *EdwardsPoint, a *scalar.Scalar, A *EdwardsPoint, b *scalar.Scalar, C *EdwardsPoint) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsMulAbglsvPorninVartimeVector(out, a, A, b, C)
	default:
		return edwardsMulAbglsvPorninVartimeGeneric(out, a, A, b, C)
	}
}

func edwardsMultiscalarMulStraus(out *EdwardsPoint, scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsMultiscalarMulStrausVector(out, scalars, points)
	default:
		return edwardsMultiscalarMulStrausGeneric(out, scalars, points)
	}
}

func edwardsMultiscalarMulStrausVartime(out *EdwardsPoint, scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsMultiscalarMulStrausVartimeVector(out, scalars, points)
	default:
		return edwardsMultiscalarMulStrausVartimeGeneric(out, scalars, points)
	}
}

func edwardsMultiscalarMulPippengerVartime(out *EdwardsPoint, scalars []*scalar.Scalar, points []*EdwardsPoint) *EdwardsPoint {
	switch supportsVectorizedEdwards {
	case true:
		return edwardsMultiscalarMulPippengerVartimeVector(out, scalars, points)
	default:
		return edwardsMultiscalarMulPippengerVartimeGeneric(out, scalars, points)
	}
}
