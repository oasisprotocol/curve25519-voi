// Copyright (c) 2021 Oasis Labs Inc. All rights reserved.
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
	"crypto/rand"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// ExampleBasic demonstrates basic functionality.
func ExampleBasic() { //nolint: govet
	// Basic operations are API compatible with crypto/ed25519, as in
	// curve25519-voi implements a superset of the crypto/ed25519 API.

	msg := []byte("test message")

	// Key generation
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("ed25519.GenerateKey: " + err.Error())
	}

	// Signing
	sig := ed25519.Sign(privateKey, msg)

	// Verification
	if !ed25519.Verify(publicKey, msg, sig) {
		panic("ed25519.Verify: failed")
	}

	// Verification semantics are incompatible with crypto/ed25519
	// by default.  It is possible to generate signatures that will be
	// accepted by one (and rejected by the other), though this will
	// NEVER happen during normal operation.
	//
	// If exact compatibility with the standard library is required
	// then VerifyWithOptions must be used with the appropriate options.
	//
	// Note: Over 99% of the users do not need this, the various edge
	// case incompatiblities are systemic across the whole Ed25519
	// ecosystem as a whole, and RFC 8032 explicitly allows for this
	// situation.
	opts := &ed25519.Options{
		Verify: ed25519.VerifyOptionsStdLib,
	}
	if !ed25519.VerifyWithOptions(publicKey, msg, sig, opts) {
		panic("ed25519.VerifyWithOptions: failed")
	}

	fmt.Println("ok")
	// Output: ok
}
