// Copyright (c) 2020 Henry de Valence. All rights reserved.
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
	"io"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

// BatchVerifier accumulates batch entries with Add, before performing
// batch verifcation with Verify.
type BatchVerifier struct {
	entries []entry

	anyInvalid      bool
	anyCofactorless bool
}

type entry struct {
	signature []byte

	// Note: Unlike ed25519consensus, this stores R, and A, and S
	// in the entry, so that it is possible to implement a more
	// useful verification API (information about which signature(s)
	// are invalid is wanted a lot of the time), without having to
	// redo a non-trivial amount of computation.
	//
	// In terms of total heap space consumed to verify a given batch,
	// this adds ~`2*sizeof(scalar.Scalar)` bytes per entry.
	R    curve.EdwardsPoint
	A    curve.EdwardsPoint
	S    scalar.Scalar
	hram scalar.Scalar

	wantCofactorless bool
	canBeValid       bool
}

func (e *entry) doInit(publicKey, message, sig []byte, opts *Options) {
	// Until everything has been deserialized correctly, assume the
	// entry is totally invalid.
	e.canBeValid = false

	fBase, context, err := opts.verify()
	if err != nil {
		return
	}
	vOpts := opts.Verify
	if vOpts == nil {
		vOpts = VerifyOptionsDefault
	}

	// This is nonsensical (as in, cofactorless batch-verification
	// is flat out incorrect), but the API allows for requesting it.
	if e.wantCofactorless = vOpts.CofactorlessVerify; e.wantCofactorless {
		e.signature = sig
	}

	// Deserialize R, A, and S.
	//
	// TODO/perf: The clever thing to do would be to decouple A from
	// the rest of the entry contents so that it is possible to avoid
	// having to decompress public keys repeatedly.  Though at that
	// point dalek's `VartimeEdwardsPrecomputation` also starts to
	// look attractive.
	if ok := vOpts.unpackPublicKey(publicKey, &e.A); !ok {
		return
	}
	if ok := vOpts.unpackSignature(sig, &e.R, &e.S); !ok {
		return
	}

	// Calculate H(R,A,m).
	var (
		f dom2Flag

		hash [64]byte
		h    = sha512.New()
	)

	if f, err = checkHash(fBase, message, opts.HashFunc()); err != nil {
		return
	}

	if dom2 := makeDom2(f, context); dom2 != nil {
		_, _ = h.Write(dom2)
	}
	_, _ = h.Write(sig[:32])
	_, _ = h.Write(publicKey[:])
	_, _ = h.Write(message)
	h.Sum(hash[:0])
	if _, err = e.hram.SetBytesModOrderWide(hash[:]); err != nil {
		return
	}

	// Ok, R, A, S, and hram can at least be deserialized/computed,
	// so it is possible for the entry to be valid.
	e.canBeValid = true
}

// Add adds a (public key, message, sig) triple to the current batch.
func (v *BatchVerifier) Add(publicKey PublicKey, message, sig []byte) {
	v.AddWithOptions(publicKey, message, sig, optionsDefault)
}

// AddWithOptions adds a (public key, message, sig, opts) quad to the
// current batch.
//
// WARNING: This routine will panic if opts is nil.
func (v *BatchVerifier) AddWithOptions(publicKey PublicKey, message, sig []byte, opts *Options) {
	var e entry

	e.doInit(publicKey, message, sig, opts)
	v.anyInvalid = v.anyInvalid || !e.canBeValid
	v.anyCofactorless = v.anyCofactorless || e.wantCofactorless
	v.entries = append(v.entries, e)
}

// VerifyBatchOnly checks all entries in the current batch using entropy
// from rand, returning true if all entries are valid and false if any one
// entry is invalid.  If rand is nil, crypto/rand.Reader will be used.
//
// If a failure arises it is unknown which entry failed, the caller must
// verify each entry individually.
//
// Calling Verify on an empty batch, or a batch containing any entries that
// specifiy cofactor-less verification will return false.
func (v *BatchVerifier) VerifyBatchOnly(rand io.Reader) bool {
	if rand == nil {
		rand = cryptorand.Reader
	}

	vl := len(v.entries)
	numTerms := 1 + vl + vl

	// Handle some early aborts.
	switch {
	case vl == 0:
		// Abort early on an empty batch, which probably indicates a bug
		return false
	case v.anyInvalid:
		// Abort early if any of the `Add`/`AddWithOptions` calls failed
		// to fully execute, since at least one entry is invalid.
		return false
	case v.anyCofactorless:
		// Abort early if any of the entries requested cofactor-less
		// verification, since that flat out doesn't work.
		return false
	}

	// The batch verification equation is
	//
	// [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
	// where for each signature i,
	// - A_i is the verification key;
	// - R_i is the signature's R value;
	// - s_i is the signature's s value;
	// - k_i is the hash of the message and other data;
	// - z_i is a random 128-bit Scalar.
	svals := make([]scalar.Scalar, numTerms)
	scalars := make([]*scalar.Scalar, numTerms)

	// Populate scalars variable with concrete scalars to reduce heap allocation
	for i := range scalars {
		scalars[i] = &svals[i]
	}

	Bcoeff := scalars[0]
	Rcoeffs := scalars[1 : 1+vl]
	Acoeffs := scalars[1+vl:]

	// No need to allocate a backing-store since B, Rs and As already
	// have concrete instances.
	points := make([]*curve.EdwardsPoint, numTerms)

	points[0] = curve.ED25519_BASEPOINT_POINT // B
	var randomBytes [scalar.ScalarWideSize]byte
	for i := range v.entries {
		// Avoid range copying each v.entries[i] literal.
		entry := &v.entries[i]
		points[1+i] = &entry.R
		points[1+vl+i] = &entry.A

		// An inquisitive reader would ask why this doesn't just do
		// `z.SetRandom(rand)`, and instead, opts to duplicate the code.
		//
		// Go's escape analysis fails to realize that `randomBytes`
		// doesn't escape, so doing this saves n-1 allocations,
		// which can be quite large, especially as the batch size
		// increases.
		if _, err := io.ReadFull(rand, randomBytes[:]); err != nil {
			return false
		}
		if _, err := Rcoeffs[i].SetBytesModOrderWide(randomBytes[:]); err != nil {
			return false
		}

		var sz scalar.Scalar
		Bcoeff.Add(Bcoeff, sz.Mul(Rcoeffs[i], &entry.S))

		Acoeffs[i].Mul(Rcoeffs[i], &entry.hram)
	}
	Bcoeff.Neg(Bcoeff) // this term is subtracted in the summation

	// Check the cofactored batch verification equation.
	var shouldBeId curve.EdwardsPoint
	shouldBeId.MultiscalarMulVartime(scalars, points)
	return shouldBeId.IsSmallOrder()
}

// Verify checks all entries in the current batch using entropy from rand,
// returning true if all entries in the current bach are valid.  If one or
// more signature is invalid, each entry in the batch will be verified
// serially, and the returned bit-vector will provide information about
// each individual entry.  If rand is nil, crypto/rand.Reader will be used.
//
// Note: Unless specific information about which signature(s) were invalid
// is not required, calling Verify will be faster than VerifyBatchOnly
// followed by serial verification in the event of a failure.
func (v *BatchVerifier) Verify(rand io.Reader) (bool, []bool) {
	vl := len(v.entries)
	if vl == 0 {
		return false, nil
	}

	// Start by assuming everything is valid, unless we know for sure
	// otherwise (ie: public key/signature/options were malformed).
	valid := make([]bool, vl)
	for i := range v.entries {
		valid[i] = v.entries[i].canBeValid
	}

	// If batch verification is possible, do the batch verification.
	if !v.anyInvalid && !v.anyCofactorless {
		if v.VerifyBatchOnly(rand) {
			// Fast-path, the entire batch is valid.
			return true, valid
		}
	}

	// Slow-path, one or more signatures is either invalid, or needs
	// cofactor-less verification.
	//
	// Note: In the case of the latter it is still possible for the
	// entire batch to be valid, but it is incorrect to trust the
	// batch verification results.
	allValid := !v.anyInvalid
	for i := range v.entries {
		// If the entry is known to be invalid, skip the serial
		// verification.
		if !valid[i] {
			continue
		}

		entry := &v.entries[i]

		var Aneg curve.EdwardsPoint
		Aneg.Neg(&entry.A)

		switch entry.wantCofactorless {
		case true:
			var R curve.EdwardsPoint
			R.DoubleScalarMulBasepointVartime(&entry.hram, &Aneg, &entry.S)
			valid[i] = cofactorlessVerify(&R, entry.signature)
		case false:
			var rDiff curve.EdwardsPoint
			rDiff.TripleScalarMulBasepointVartime(&entry.hram, &Aneg, &entry.S, &entry.R)
			valid[i] = rDiff.IsSmallOrder()
		}
		allValid = allValid && valid[i]
	}

	return allValid, valid
}

// NewBatchVerfier creates an empty BatchVerifier.
func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{}
}
