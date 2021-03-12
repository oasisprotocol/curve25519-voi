// Copyright (c) 2017-2019 Isis Agora Lovecruft. All rights reserved.
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

package ed25519

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

// VerifyBatch reports whether sigs are valid signatures of messages by
// publicKeys, using entropy from rand.  If rand is nil, crypto/rand.Reader
// will be used.  For convenience, the function will return true iff
// every single signature is valid.
//
// Batch verification MUST use the cofactored verification equation to
// produce correct results.  If VerifyOptions is set to cofactorless
// verification, this routine will fall back to serial verification of
// each signature.
//
// Note: Unlike VerifyWithOptions, this routine will not panic on malformed
// inputs in the batch, and instead just mark the particular signature as
// having failed verification.
func VerifyBatch(rand io.Reader, publicKeys []PublicKey, messages, sigs [][]byte, opts *Options) (bool, []bool, error) {
	const rsOffsetStart = 1

	if rand == nil {
		rand = cryptorand.Reader
	}

	fBase, context, err := opts.verify()
	if err != nil {
		return false, nil, err
	}
	vOpts := opts.Verify
	if vOpts == nil {
		vOpts = VerifyOptionsDefault
	}

	num := len(publicKeys)
	if num != len(messages) || len(messages) != len(sigs) {
		return false, nil, fmt.Errorf("ed25519: argument count mismatch")
	}
	if num == 0 {
		return false, nil, fmt.Errorf("ed25519: empty batches are not supported")
	}

	// Start under the assumption that everything is valid.
	valid := make([]bool, num)
	for i := range valid {
		valid[i] = true
	}
	allValid := true

	// Unpack publicKeys/sigs into A, R and S, and compute H(R || A || M).
	var (
		numItems = num + num

		scalars      = make([]*scalar.Scalar, numItems) // Ss || hrams
		scalarsStore = make([]scalar.Scalar, numItems)

		points      = make([]*curve.EdwardsPoint, 1+numItems) // B || Rs || As
		pointsStore = make([]curve.EdwardsPoint, numItems)

		h    = sha512.New()
		hash [64]byte

		Rs    = points[rsOffsetStart : rsOffsetStart+num]
		As    = points[rsOffsetStart+num:]
		Ss    = scalars[0:num]
		hrams = scalars[num:]
	)
	points[0] = curve.ED25519_BASEPOINT_POINT
	for i := 0; i < numItems; i++ {
		scalars[i] = &scalarsStore[i]
		points[rsOffsetStart+i] = &pointsStore[i]
	}

	for i := 0; i < num; i++ {
		if valid[i] = vOpts.unpackPublicKey(publicKeys[i], As[i]); !valid[i] {
			allValid = false
			continue
		}

		if valid[i] = vOpts.unpackSignature(sigs[i], Rs[i], Ss[i]); !valid[i] {
			allValid = false
			continue
		}

		var f dom2Flag
		if f, err = checkHash(fBase, messages[i], opts.HashFunc()); err != nil {
			valid[i], allValid = false, false
			continue
		}

		if dom2 := makeDom2(f, context); dom2 != nil {
			_, _ = h.Write(dom2)
		}
		_, _ = h.Write(sigs[i][:32])
		_, _ = h.Write(publicKeys[i][:])
		_, _ = h.Write(messages[i])
		h.Sum(hash[:0])
		if _, err = hrams[i].SetBytesModOrderWide(hash[:]); err != nil {
			valid[i], allValid = false, false
			continue
		}
		h.Reset()
	}

	// Only actually try to do the batch verification if allowed by
	// the verification options.
	if allValid && !vOpts.CofactorlessVerify {
		// This doesn't update allValid since the serial path
		// handles explicitly setting after checking each signature.
		if doBatchVerify(rand, points, Ss, hrams) {
			return allValid, valid, nil
		}
	}

	// If execution reaches this point, either it was not possible to
	// do batch verification, or batch verification claims that at
	// least one signature is invalid.  Fall back to serial verification.
	for i := 0; i < num; i++ {
		// If the signature is already known to be invalid, skip
		// actually doing the verification.
		if !valid[i] {
			continue
		}

		// Instead of calling verifyWithOptionsNoPanic, just do the
		// final calculation to save some computation.
		As[i].Neg(As[i])

		switch vOpts.CofactorlessVerify {
		case true:
			var R curve.EdwardsPoint
			R.DoubleScalarMulBasepointVartime(hrams[i], As[i], Ss[i])
			valid[i] = cofactorlessVerify(&R, sigs[i])
		case false:
			var rDiff curve.EdwardsPoint
			rDiff.TripleScalarMulBasepointVartime(hrams[i], As[i], Ss[i], Rs[i])
			valid[i] = rDiff.IsSmallOrder()
		}
		if !valid[i] {
			allValid = false
		}
	}

	return allValid, valid, nil
}

func doBatchVerify(rand io.Reader, points []*curve.EdwardsPoint, Ss, hrams []*scalar.Scalar) bool {
	// Note: points is assumed to contain B || Rs || As
	const zsOffsetStart = 1

	var (
		num          = len(Ss)
		numTerms     = 1 + num + num
		scalars      = make([]*scalar.Scalar, numTerms) // B_coefficient || zs || zhrams
		scalarsStore = make([]scalar.Scalar, numTerms)

		zs     = scalars[zsOffsetStart : zsOffsetStart+num]
		zhrams = scalars[zsOffsetStart+num:]
	)
	for i := range scalars {
		scalars[i] = &scalarsStore[i]
	}

	// Select a random 128-bit scalar for each signature.
	var scalarBytes [scalar.ScalarWideSize]byte
	for i := 0; i < num; i++ {
		// An inquisitive reader would ask why this doesn't just do
		// `z.SetRandom(rand)`, and instead, opts to duplicate the code.
		//
		// Go's escape analysis fails to realize that `scalarBytes`
		// doesn't escape, so doing this saves n-1 allocations,
		// which can be quite large, especially as the batch size
		// increases.
		z := zs[i]
		if _, err := io.ReadFull(rand, scalarBytes[:]); err != nil {
			return false
		}
		if _, err := z.SetBytesModOrderWide(scalarBytes[:]); err != nil {
			return false
		}
	}

	// Compute the basepoint coefficient, sum(s[i]z[i]) (mod l).
	B_coefficient := scalars[0]
	for i := 0; i < num; i++ {
		var sz scalar.Scalar
		B_coefficient.Add(B_coefficient, sz.Mul(zs[i], Ss[i]))
	}
	B_coefficient.Neg(B_coefficient) // ... and negate it.

	// Multiply each H(R || A || M) by the random value.
	for i := 0; i < num; i++ {
		zhrams[i].Mul(zs[i], hrams[i])
	}

	// Check the cofactored batch verification equation.
	var id curve.EdwardsPoint
	id.MultiscalarMulVartime(scalars, points)
	return id.IsSmallOrder()
}
