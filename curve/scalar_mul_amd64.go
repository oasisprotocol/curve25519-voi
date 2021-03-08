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

func newEdwardsBasepointTable(basepoint *EdwardsPoint) edwardsBasepointTableImpl {
	switch supportsVectorizedEdwards {
	case true:
		return newEdwardsBasepointTableVector(basepoint)
	default:
		return newEdwardsBasepointTableGeneric(basepoint)
	}
}
