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
	"strconv"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

var (
	benchBatchSizes       = []int{1, 2, 4, 8, 16}
	benchMultiscalarSizes = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 512, 768, 1024}
)

func BenchmarkEdwards(b *testing.B) {
	b.Run("Compress", benchEdwardsCompress)
	b.Run("Decompress", benchEdwardsDecompress)
	b.Run("Mul", benchEdwardsMul)
	b.Run("BasepointTable/Mul", benchEdwardsBasepointTableMul)
	b.Run("DoubleScalarMulBasepointVartime", benchEdwardsDoubleScalarMulBasepointVartime)
	b.Run("MultiscalarMul", benchEdwardsMultiscalarMul)
	b.Run("MultiscalarMulVartime", benchEdwardsMultiscalarMulVartime)
}

func benchEdwardsCompress(b *testing.B) {
	var compressed CompressedEdwardsY
	for i := 0; i < b.N; i++ {
		compressed.FromEdwardsPoint(&ED25519_BASEPOINT_POINT)
	}
}

func benchEdwardsDecompress(b *testing.B) {
	var decompressed EdwardsPoint
	for i := 0; i < b.N; i++ {
		if err := decompressed.FromCompressedY(&ED25519_BASEPOINT_COMPRESSED); err != nil {
			b.Fatalf("FromCompressedY(): %v", err)
		}
	}
}

func benchEdwardsMul(b *testing.B) {
	s := scalar.NewFromUint64(897987897)
	s.Invert()

	b.ResetTimer()

	var tmp EdwardsPoint
	for i := 0; i < b.N; i++ {
		tmp.Mul(&ED25519_BASEPOINT_POINT, &s)
	}
}

func benchEdwardsBasepointTableMul(b *testing.B) {
	s := scalar.NewFromUint64(897987897)
	s.Invert()

	b.ResetTimer()

	var tmp EdwardsPoint
	for i := 0; i < b.N; i++ {
		tmp = ED25519_BASEPOINT_TABLE.Mul(&s)
	}
	_ = tmp // Shut up compiler.
}

func benchEdwardsDoubleScalarMulBasepointVartime(b *testing.B) {
	A := ED25519_BASEPOINT_TABLE.Mul(newBenchRandomScalar(b))

	b.ResetTimer()

	var tmp EdwardsPoint
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		aScalar, bScalar := newBenchRandomScalar(b), newBenchRandomScalar(b)
		b.StartTimer()

		tmp.DoubleScalarMulBasepointVartime(aScalar, &A, bScalar)
	}
}

func benchEdwardsMultiscalarMulIter(b *testing.B, n int, isVartime bool) {
	points := newBenchRandomPoints(b, n)

	b.ResetTimer()

	var tmp EdwardsPoint
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		scalars := newBenchRandomScalars(b, n)
		b.StartTimer()

		if isVartime {
			tmp.MultiscalarMulVartime(scalars, points)
		} else {
			tmp.MultiscalarMul(scalars, points)
		}
	}
}

func benchEdwardsMultiscalarMul(b *testing.B) {
	for _, n := range benchMultiscalarSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			benchEdwardsMultiscalarMulIter(b, n, false)
		})
	}
}

func benchEdwardsMultiscalarMulVartime(b *testing.B) {
	for _, n := range benchMultiscalarSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			benchEdwardsMultiscalarMulIter(b, n, true)
		})
	}
}

func BenchmarkRistretto(b *testing.B) {
	b.Run("Compress", benchRistrettoCompress)
	b.Run("Decompress", benchRistrettoDecompress)
}

func benchRistrettoCompress(b *testing.B) {
	var compressed CompressedRistretto
	for i := 0; i < b.N; i++ {
		compressed.FromRistrettoPoint(&RISTRETTO_BASEPOINT_POINT)
	}
}

func benchRistrettoDecompress(b *testing.B) {
	var decompressed RistrettoPoint
	for i := 0; i < b.N; i++ {
		if err := decompressed.FromCompressed(&RISTRETTO_BASEPOINT_COMPRESSED); err != nil {
			b.Fatalf("FromRistrettoPoint(): %v", err)
		}
	}
}

func BenchmarkMontgomery(b *testing.B) {
	b.Run("Mul", benchMontgomeryMul)
}

func benchMontgomeryMul(b *testing.B) {
	s := scalar.NewFromUint64(897987897)
	s.Invert()

	b.ResetTimer()

	var tmp MontgomeryPoint
	for i := 0; i < b.N; i++ {
		tmp.Mul(&X25519_BASEPOINT, &s)
	}
}

func BenchmarkScalar(b *testing.B) {
	b.Run("Invert", benchScalarInvert)
	b.Run("BatchInvert", benchScalarBatchInvert)
}

func benchScalarInvert(b *testing.B) {
	s := scalar.NewFromUint64(897987897)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.Invert()
	}
}

func benchScalarBatchInvertIter(b *testing.B, n int) {
	scalars := newBenchRandomScalars(b, n)

	b.ResetTimer()

	var s scalar.Scalar
	for i := 0; i < b.N; i++ {
		s.BatchInvert(scalars)
	}
}

func benchScalarBatchInvert(b *testing.B) {
	for _, n := range benchBatchSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			benchScalarBatchInvertIter(b, n)
		})
	}
}

func newBenchRandomScalar(b *testing.B) *scalar.Scalar {
	var s scalar.Scalar
	if err := s.Random(rand.Reader); err != nil {
		b.Fatalf("s.Random(): %v", err)
	}
	return &s
}

func newBenchRandomScalars(b *testing.B, n int) []*scalar.Scalar {
	v := make([]*scalar.Scalar, 0, n)
	for i := 0; i < n; i++ {
		v = append(v, newBenchRandomScalar(b))
	}
	return v
}

func newBenchRandomPoints(b *testing.B, n int) []*EdwardsPoint {
	v := make([]*EdwardsPoint, 0, n)
	for i := 0; i < n; i++ {
		p := ED25519_BASEPOINT_TABLE.Mul(newBenchRandomScalar(b))
		v = append(v, &p)
	}
	return v
}