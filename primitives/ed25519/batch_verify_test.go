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
	"crypto/rand"
	"io"
	"strconv"
	"testing"
)

type batchTest int

const (
	batchNoErrors batchTest = iota
	batchWrongMessage
	batchWrongPk
	batchWrongSig
	batchMalformedPk
	batchMalformedSig
	batchMalformedPh

	testBatchSize = 64
)

func testBatchInit(tb testing.TB, r io.Reader, batchSize int, opts *Options) ([]PublicKey, [][]byte, [][]byte) {
	sks := make([]PrivateKey, batchSize)
	pks := make([]PublicKey, batchSize)
	sigs := make([][]byte, batchSize)
	messages := make([][]byte, batchSize)

	// generate keys
	for i := 0; i < batchSize; i++ {
		pub, priv, err := GenerateKey(r)
		if err != nil {
			tb.Fatalf("failed to generate key #%d: %v", i, err)
		}

		sks[i], pks[i] = priv, pub
	}

	// generate messages
	for i := 0; i < batchSize; i++ {
		mLen := (i & 127) + 1
		m := make([]byte, mLen)
		if _, err := io.ReadFull(r, m); err != nil {
			tb.Fatalf("failed to generate message #%d: %v", i, err)
		}
		messages[i] = m

		// Pre-hash the message if required.
		if opts.Hash != crypto.Hash(0) {
			h := opts.Hash.New()
			_, _ = h.Write(messages[i])
			messages[i] = h.Sum(nil)
		}
	}

	// sign messages
	for i := 0; i < batchSize; i++ {
		sig, err := sks[i].Sign(nil, messages[i], opts)
		if err != nil {
			tb.Fatalf("failed to generate signature #%d: %v", i, err)
		}
		sigs[i] = sig
	}

	return pks, sigs, messages
}

func testBatchInstance(t *testing.T, tst batchTest, r io.Reader, opts *Options) {
	pks, sigs, messages := testBatchInit(t, r, testBatchSize, opts)

	// mess things up (if required)
	var expectedRet bool
	switch tst {
	case batchNoErrors:
		expectedRet = true
	case batchWrongMessage:
		messages[0] = messages[1]
	case batchWrongPk:
		pks[0] = pks[1]
	case batchWrongSig:
		sigs[0] = sigs[1]
	case batchMalformedPk:
		pks[0] = []byte("truncated pk")
	case batchMalformedSig:
		sigs[0] = []byte("truncated sig")
	case batchMalformedPh:
		messages[0] = []byte("bad digest")
	}

	// Ensure the 0th signature verification done singularly, gives
	// the expected result.
	sigOk, _ := verifyWithOptionsNoPanic(pks[0], messages[0], sigs[0], opts)
	if sigOk != expectedRet {
		t.Fatalf("failed to force failure: %v", tst)
	}

	// verify the batch
	ok, valid, err := VerifyBatch(r, pks[:], messages[:], sigs[:], opts)
	if err != nil {
		t.Fatalf("failed to verify batch: %v", err)
	}

	// validate the results
	if ok != expectedRet {
		t.Errorf("unexpected batch return code: %v (expected: %v)", ok, expectedRet)
	}
	if len(valid) != testBatchSize {
		t.Errorf("unexpected batch validity vector length: %v (expected: %v)", len(valid), testBatchSize)
	}
	for i, v := range valid {
		expectedValid := expectedRet
		if i != 0 {
			// The negative tests only mess up the 0th entry.
			expectedValid = true
		}
		if v != expectedValid {
			t.Errorf("unexpected batch element return code #%v: %v (expected: %v)", i, v, expectedValid)
		}
	}
}

func testVerifyBatchOpts(t *testing.T, opts *Options) {
	t.Run("NoErrors", func(t *testing.T) {
		testBatchInstance(t, batchNoErrors, rand.Reader, opts)
	})

	const nrFailTestRuns = 4
	t.Run("WrongMessage", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongMessage, rand.Reader, opts)
		}
	})
	t.Run("WrongPublicKey", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongPk, rand.Reader, opts)
		}
	})
	t.Run("WrongSignature", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongSig, rand.Reader, opts)
		}
	})
	t.Run("MalformedPublicKey", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchMalformedPk, rand.Reader, opts)
		}
	})
	t.Run("MalformedSignature", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchMalformedSig, rand.Reader, opts)
		}
	})
	if opts.Hash != crypto.Hash(0) {
		t.Run("MalformedPreHash", func(t *testing.T) {
			for i := 0; i < nrFailTestRuns; i++ {
				testBatchInstance(t, batchMalformedPh, rand.Reader, opts)
			}
		})
	}
}

func TestVerifyBatch(t *testing.T) {
	t.Run("Ed25519pure", func(t *testing.T) {
		testVerifyBatchOpts(t, &Options{})
	})
	t.Run("Ed25519ctx", func(t *testing.T) {
		testVerifyBatchOpts(t, &Options{
			Context: "test ed25519ctx batch verify",
		})
	})
	t.Run("Ed25519ph", func(t *testing.T) {
		testVerifyBatchOpts(t, &Options{
			Hash:    crypto.SHA512,
			Context: "test ed25519ph batch verify",
		})
	})
}

func BenchmarkVerifyBatch(b *testing.B) {
	benchBatchSizes := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 512, 768, 1024}
	for _, n := range benchBatchSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			benchmarkVerifyBatchIter(b, n)
		})
	}
}

func benchmarkVerifyBatchIter(b *testing.B, n int) {
	var opts Options
	pks, sigs, messages := testBatchInit(b, rand.Reader, n, &opts)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ok, _, _ := VerifyBatch(nil, pks[:], messages[:], sigs[:], &opts)
		if !ok {
			b.Fatalf("unexpected batch verification failure!")
		}
	}
}
