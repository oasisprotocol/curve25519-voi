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
//    * Neither the name of the copyright holder nor the names of its
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

package cache

import (
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

const testCacheSize = 10

var testMsg = []byte("This is only a test of the emergency broadcast system")

func BenchmarkCache(b *testing.B) {
	b.Run("Verify/Miss", benchCacheMiss)
	b.Run("Verify/Hit", benchCacheHit)
}

func benchCacheMiss(b *testing.B) {
	v := NewVerifier(NewLRUCache(testCacheSize))

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			b.Fatalf("failed to generate key: %v", err)
		}
		sig := ed25519.Sign(priv, testMsg)
		b.StartTimer()

		if !v.Verify(pub, testMsg, sig) {
			b.Fatalf("failed to verify signature")
		}
	}
}

func benchCacheHit(b *testing.B) {
	v := NewVerifier(NewLRUCache(testCacheSize))

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}
	v.AddPublicKey(pub)
	sig := ed25519.Sign(priv, testMsg)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !v.Verify(pub, testMsg, sig) {
			b.Fatalf("failed to verify signature")
		}
	}
}
