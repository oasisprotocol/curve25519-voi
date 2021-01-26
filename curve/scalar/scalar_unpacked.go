// Copyright (c) 2016-2019 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
// Copyright (c) 2020-2021 Oasis Labs Inc.  All rights reserved.
// Portions Copyright 2017 Brian Smith.
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

package scalar

// mul computes `a * b` (mod l).
func (s *unpackedScalar) mul(a, b *unpackedScalar) {
	limbs := scalarMulInternal(a, b)
	s.montgomeryReduce(&limbs)
	limbs = scalarMulInternal(s, &constRR)
	s.montgomeryReduce(&limbs)
}

// square computes `a^2` (mod l).
func (s *unpackedScalar) square() {
	limbs := s.squareInternal()
	s.montgomeryReduce(&limbs)
	limbs = scalarMulInternal(s, &constRR)
	s.montgomeryReduce(&limbs)
}

// montgomeryMul computes `(a * b) / R` (mod l), where R is the Montgomery
// modulus 2^260.
func (s *unpackedScalar) montgomeryMul(a, b *unpackedScalar) {
	limbs := scalarMulInternal(a, b)
	s.montgomeryReduce(&limbs)
}

// montgomerySquare computes `(a^2) / R` (mod l), where R is the Montgomery
// modulus 2^260.
func (s *unpackedScalar) montgomerySquare() {
	limbs := s.squareInternal()
	s.montgomeryReduce(&limbs)
}

// toMontgomery puts the scalar in to Montgomery form, i.e. computes `a*R (mod l)`.
func (s *unpackedScalar) toMontgomery() {
	s.montgomeryMul(s, &constRR)
}

// montgomeryInvert inverts an unpackedScalar in Montgomery form.
func (us *unpackedScalar) montgomeryInvert() {
	// Uses the addition chain from
	// https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
	var c1, c10, c100, c11, c101, c111, c1001, c1011, c1111 unpackedScalar
	c1 = *us
	c10 = c1
	c10.montgomerySquare()
	c100 = c10
	c100.montgomerySquare()
	c11.montgomeryMul(&c10, &c1)
	c101.montgomeryMul(&c10, &c11)
	c111.montgomeryMul(&c10, &c101)
	c1001.montgomeryMul(&c10, &c111)
	c1011.montgomeryMul(&c10, &c1001)
	c1111.montgomeryMul(&c100, &c1011)

	// _10000
	y := us
	y.montgomeryMul(&c1111, &c1)

	// montgomerySquareMultiply used to be just a function local to
	// montgomeryInvert, but Go's overly primitive escape analysis
	// starts moving things to the heap.

	y.montgomerySquareMultiply(123+3, &c101)
	y.montgomerySquareMultiply(2+2, &c11)
	y.montgomerySquareMultiply(1+4, &c1111)
	y.montgomerySquareMultiply(1+4, &c1111)
	y.montgomerySquareMultiply(4, &c1001)
	y.montgomerySquareMultiply(2, &c11)
	y.montgomerySquareMultiply(1+4, &c1111)
	y.montgomerySquareMultiply(1+3, &c101)
	y.montgomerySquareMultiply(3+3, &c101)
	y.montgomerySquareMultiply(3, &c111)
	y.montgomerySquareMultiply(1+4, &c1111)
	y.montgomerySquareMultiply(2+3, &c111)
	y.montgomerySquareMultiply(2+2, &c11)
	y.montgomerySquareMultiply(1+4, &c1011)
	y.montgomerySquareMultiply(2+4, &c1011)
	y.montgomerySquareMultiply(6+4, &c1001)
	y.montgomerySquareMultiply(2+2, &c11)
	y.montgomerySquareMultiply(3+2, &c11)
	y.montgomerySquareMultiply(3+2, &c11)
	y.montgomerySquareMultiply(1+4, &c1001)
	y.montgomerySquareMultiply(1+3, &c111)
	y.montgomerySquareMultiply(2+4, &c1111)
	y.montgomerySquareMultiply(1+4, &c1011)
	y.montgomerySquareMultiply(3, &c101)
	y.montgomerySquareMultiply(2+4, &c1111)
	y.montgomerySquareMultiply(3, &c101)
	y.montgomerySquareMultiply(1+2, &c11)
}

func (us *unpackedScalar) montgomerySquareMultiply(squarings uint, x *unpackedScalar) {
	for i := uint(0); i < squarings; i++ {
		us.montgomerySquare()
	}
	us.montgomeryMul(us, x)
}

// Invert sets the nonzero scalar to its multiplicative inverse.
func (us *unpackedScalar) Invert() {
	us.toMontgomery()
	us.montgomeryInvert()
	us.fromMontgomery()
}