// Copyright (c) 2021 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Oasis Labs Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ed25519

import (
	"crypto"
	"fmt"
	"testing"
)

type batchTest int

const (
	batchNoErrors batchTest = iota
	batchShortSig
	batchCorruptKey
	batchCorruptSignatureR
	batchCorruptSignatureS
	batchCorruptMessage
	batchMalformedKey
	batchMalformedSig
	batchMalformedPh
	batchMalformedCtx

	testBatchSize = 38
)

type batchVerifierTestCase struct {
	n          string
	tst        batchTest
	culpritIdx int
	details    string
}

var batchTestCases = []*batchVerifierTestCase{
	{
		"Verify",
		batchNoErrors,
		-1,
		"failed batch verification",
	},
	{
		"FailsOnShortSig",
		batchShortSig,
		0,
		"batch verification should fail due to short signature",
	},
	{
		"FailsOnCorruptKey",
		batchCorruptKey,
		1,
		"batch verification should fail due to corrupt key",
	},
	{
		"FailsOnCorruptSignature/R",
		batchCorruptSignatureR,
		2,
		"batch verification should fail due to corrupt signature (R)",
	},
	{
		"FailsOnCorruptSignature/S",
		batchCorruptSignatureS,
		3,
		"batch verification should fail due to corrupt signature (S)",
	},
	{
		"FailsOnCorruptMessage",
		batchCorruptMessage,
		4,
		"batch verification should fail due to corrupt message",
	},
	{
		"FailsOnMalformedKey",
		batchMalformedKey,
		5,
		"batch verification should fail due to malformed key",
	},
	{
		"FailsOnMalformedSignature",
		batchMalformedSig,
		6,
		"batch verification should fail due to malformed signature",
	},
}

func (tc *batchVerifierTestCase) makeVerifier(t *testing.T, opts *Options) *BatchVerifier {
	const n = 38

	v := NewBatchVerifier()
	privs := make([]PrivateKey, 0, n)
	pubs := make([]PublicKey, 0, n)
	msgs := make([][]byte, 0, n)
	sigs := make([][]byte, 0, n)
	optsVec := make([]*Options, 0, n)

	for i := 0; i <= testBatchSize; i++ {
		pub, priv, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to GenerateKey: %v", err)
		}

		var msg []byte
		if i%2 == 0 {
			msg = []byte("easter")
		} else {
			msg = []byte("egg")
		}
		if opts != nil && opts.Hash != 0 {
			h := opts.HashFunc().New()
			_, _ = h.Write(msg)
			msg = h.Sum(nil)
		}

		privs = append(privs, priv)
		pubs = append(pubs, pub)
		msgs = append(msgs, msg)
		optsVec = append(optsVec, opts)
	}

	// If the test case calls for it, introduce errors in the batch.
	culpritIdx := tc.culpritIdx
	switch tc.tst {
	case batchCorruptKey:
		pubs[culpritIdx][1] ^= 1
	case batchMalformedKey:
		pubs[culpritIdx] = pubs[culpritIdx][:31]
	}

	for i := range privs {
		switch {
		case opts == nil:
			sigs = append(sigs, Sign(privs[i], msgs[i]))
		default:
			sig, err := privs[i].Sign(nil, msgs[i], opts)
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}
			sigs = append(sigs, sig)
		}
	}

	switch tc.tst {
	case batchShortSig:
		sigs[culpritIdx] = nil
	case batchCorruptSignatureR:
		sigs[culpritIdx][1] ^= 1
	case batchCorruptSignatureS:
		sigs[culpritIdx][33] ^= 1
	case batchCorruptMessage:
		msgs[culpritIdx] = []byte("not the message")
	case batchMalformedSig:
		sigs[culpritIdx] = append(sigs[culpritIdx], 23)
	case batchMalformedPh:
		msgs[culpritIdx] = []byte("not a pre-hash")
	case batchMalformedCtx:
		b := make([]byte, ContextMaxSize+1)
		for i := range b {
			b[i] = byte('a')
		}
		optsVec[culpritIdx] = &Options{
			Context: string(b),
		}
	}

	for i := range pubs {
		switch {
		case optsVec[i] == nil:
			v.Add(pubs[i], msgs[i], sigs[i])
		default:
			v.AddWithOptions(pubs[i], msgs[i], sigs[i], optsVec[i])
		}
	}

	return v
}

func (tc *batchVerifierTestCase) run(t *testing.T, opts *Options) {
	v := tc.makeVerifier(t, opts)
	expectedBatchOk := tc.culpritIdx < 0
	expectedVerifyOk := expectedBatchOk
	if opts != nil && opts.Verify != nil && opts.Verify.CofactorlessVerify {
		// Cofactor-less verification should always fail batch verify.
		expectedBatchOk = false
	}

	// First test that the batch verify returns the expected
	// result for the entire batch.
	if v.VerifyBatchOnly(nil) != expectedBatchOk {
		t.Error(tc.details)
	}

	// Then test the actually useful API.
	allValid, valid := v.Verify(nil)
	if allValid != expectedVerifyOk {
		t.Errorf("Verify returned incorrect summary (Got: %v)", allValid)
	}

	// The ensure that the bit-vector contains the expected
	// signature validity status.  tc.culpritIdx is the index
	// of the malformed/invalid signature.
	for i, sigValid := range valid {
		expectedSigOk := i != tc.culpritIdx
		if sigValid != expectedSigOk {
			t.Errorf("bit-vector %d incorrect (Got: %v)", i, sigValid)
		}
	}
}

func TestBatchVerifier(t *testing.T) {
	runTestCases := func(t *testing.T, opts *Options) {
		for _, tc := range batchTestCases {
			t.Run(tc.n, func(t *testing.T) {
				tc.run(t, opts)
			})
		}
	}

	t.Run("Ed25519pure", func(t *testing.T) {
		runTestCases(t, nil)
	})
	t.Run("Ed25519ctx", func(t *testing.T) {
		opts := &Options{
			Context: "Ed25519ctx test context",
		}
		runTestCases(t, opts)

		tc := &batchVerifierTestCase{
			"FailsOnMalformedContext",
			batchMalformedCtx,
			7,
			"batch verification should fail due to malformed context",
		}
		t.Run(tc.n, func(t *testing.T) {
			tc.run(t, opts)
		})
	})
	t.Run("Ed25519ph", func(t *testing.T) {
		opts := &Options{
			Hash: crypto.SHA512,
		}
		runTestCases(t, opts)

		tc := &batchVerifierTestCase{
			"FailsOnMalformedPreHash",
			batchMalformedPh,
			7,
			"batch verification should fail due to malformed pre-hash",
		}
		t.Run(tc.n, func(t *testing.T) {
			tc.run(t, opts)
		})
	})
	t.Run("CofactorlessFallback", func(t *testing.T) {
		runTestCases(t, &Options{
			Verify: VerifyOptionsStdLib,
		})
	})

	t.Run("EmptyBatchFails", func(t *testing.T) {
		v := NewBatchVerifier()

		if v.VerifyBatchOnly(nil) {
			t.Error("batch verification should fail on an empty batch")
		}
	})
}

func BenchmarkVerifyBatchOnly(b *testing.B) {
	benchBatchSizes := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 512, 768, 1024}
	for _, n := range benchBatchSizes {
		// Attempt to get a more accurate reflection on how much memory
		// is allocated, by pre-generating all of the batch inputs
		// prior to entering the benchmark routine, but actually
		// building the batch as part of the benchmarking process.
		pub, priv, _ := GenerateKey(nil)
		msg := []byte("BatchVerifyTest")
		sig := Sign(priv, msg)

		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Exclude the time spent so that comparisons with
				// ed25519consensus are close.
				v := NewBatchVerifier()
				for j := 0; j < n; j++ {
					v.Add(pub, msg, sig)
				}
				b.StartTimer()

				if !v.VerifyBatchOnly(nil) {
					b.Fatal("signature set failed batch verification")
				}
			}
		})
	}
}
