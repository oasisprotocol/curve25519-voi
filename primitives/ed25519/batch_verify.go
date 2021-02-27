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
		As    = make([]*curve.EdwardsPoint, num)
		Rs    = make([]*curve.EdwardsPoint, num)
		Ss    = make([]*scalar.Scalar, num)
		hrams = make([]*scalar.Scalar, num)
		h     = sha512.New()
		hash  [64]byte

		aStore    = make([]curve.EdwardsPoint, num)
		rStore    = make([]curve.EdwardsPoint, num)
		sStore    = make([]scalar.Scalar, num)
		hramStore = make([]scalar.Scalar, num)
	)
	for i := 0; i < num; i++ {
		// Regardless of if unpacking is successful, this needs to add
		// entries to each slice to simplify the serial path.
		As[i] = &aStore[i]
		Rs[i] = &rStore[i]
		Ss[i] = &sStore[i]
		hrams[i] = &hramStore[i]

		if valid[i] = vOpts.unpackPublicKey(publicKeys[i], As[i]); !valid[i] {
			allValid = false
			continue
		}

		var rCompressed curve.CompressedEdwardsY
		if valid[i] = vOpts.unpackSignature(sigs[i], &rCompressed, Rs[i], Ss[i]); !valid[i] {
			allValid = false
			continue
		}

		var f dom2Flag
		if f, err = checkHash(fBase, messages[i], opts.HashFunc()); err != nil {
			valid[i], allValid = false, false
			continue
		}

		writeDom2(h, f, context)
		_, _ = h.Write(sigs[i][:32])
		_, _ = h.Write(publicKeys[i][:])
		_, _ = h.Write(messages[i])
		h.Sum(hash[:0])
		if err = hrams[i].FromBytesModOrderWide(hash[:]); err != nil {
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
		if doBatchVerify(rand, As, Rs, Ss, hrams) {
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
		var R curve.EdwardsPoint
		As[i].Neg()
		R.DoubleScalarMulBasepointVartime(hrams[i], As[i], Ss[i])

		switch vOpts.CofactorlessVerify {
		case true:
			// Yes, this is already done once when we unpack all of
			// the signatures, but allocating a backing store to
			// save having to do this again is pointless for the
			// common case, and this call supporting cofactor-less
			// verification is merely to guard against misuse,
			// rather than something intended to be efficient.
			var RCompressed curve.CompressedEdwardsY
			err = RCompressed.FromBytes(sigs[i][:32])
			valid[i] = err == nil && R.EqualCompressedY(&RCompressed) == 1
		case false:
			var rDiff curve.EdwardsPoint
			rDiff.Sub(&R, Rs[i])
			valid[i] = rDiff.IsSmallOrder()
		}
		if !valid[i] {
			allValid = false
		}
	}

	return allValid, valid, nil
}

func doBatchVerify(rand io.Reader, As, Rs []*curve.EdwardsPoint, Ss, hrams []*scalar.Scalar) bool {
	num := len(As)

	// TODO/perf: Yes, this is more allocation/copy hungry than the
	// equivalent Rust iterator based version.

	// Select a random 128-bit scalar for each signature.
	zs := make([]*scalar.Scalar, num)
	zStore := make([]scalar.Scalar, num)
	var scalarBytes [scalar.ScalarWideSize]byte
	for i := 0; i < num; i++ {
		// An inquisitive reader would ask why this doesn't just do
		// `z.Random(rand)`, and instead, opts to duplicate the code.
		//
		// Go's escape analysis fails to realize that `scalarBytes`
		// doesn't escape, so doing this saves n-1 allocations,
		// which can be quite large, especially as the batch size
		// increases.
		z := &zStore[i]
		if _, err := io.ReadFull(rand, scalarBytes[:]); err != nil {
			return false
		}
		if err := z.FromBytesModOrderWide(scalarBytes[:]); err != nil {
			return false
		}
		zs[i] = z
	}

	// Compute the basepoint coefficient, sum(s[i]z[i]) (mod l).
	var B_coefficient scalar.Scalar
	for i := range zs {
		var sz scalar.Scalar
		sz.Mul(zs[i], Ss[i])
		B_coefficient.Add(&B_coefficient, &sz)
	}

	// Multiple each H(R || A || M) by the random value.
	zhrams := make([]*scalar.Scalar, num)
	zhramStore := make([]scalar.Scalar, num)
	for i := range zs {
		zhram := &zhramStore[i]
		zhram.Mul(zs[i], hrams[i])
		zhrams[i] = zhram
	}

	// Collect all the scalars/points to pass into the final multiscalar
	// multiply.
	scalars := make([]*scalar.Scalar, 0, 1+num+num)
	B_coefficient.Neg()
	scalars = append(scalars, &B_coefficient)
	scalars = append(scalars, zs...)
	scalars = append(scalars, zhrams...)

	points := make([]*curve.EdwardsPoint, 0, 1+num+num)
	points = append(points, &curve.ED25519_BASEPOINT_POINT)
	points = append(points, Rs...)
	points = append(points, As...)

	// Use the cofactored batch verification equation.
	var id curve.EdwardsPoint
	id.MultiscalarMulVartime(scalars, points)
	return id.IsSmallOrder()
}
