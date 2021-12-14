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
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// ExamplePhCtx demonstrates Ed25519ph and Ed25519ctx.
func ExamplePhCtx() { //nolint: govet
	// curve25519-voi supports Ed25519ph and Ed25519ctx as defined in
	// RFC 8032 in addition to Ed25519pure.

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("ed25519.GenerateKey: " + err.Error())
	}
	msg := []byte("test message")

	// Ed25519ctx
	//
	// Note: Due to Context being defined as a string, a 0-length
	// context is not supported, even though it is allowed but
	// discouraged by the RFC.
	opts := &ed25519.Options{
		Context: string("test context"),
	}
	sig, err := privateKey.Sign(nil, msg, opts)
	if err != nil {
		panic("ed25519.SignWithOptions(ctx): " + err.Error())
	}

	if !ed25519.VerifyWithOptions(publicKey, msg, sig, opts) {
		panic("ed25519.VerifyWithOptions(ctx): failed")
	}

	// Ed25519ph
	prehash := sha512.Sum512(msg)
	opts = &ed25519.Options{
		Hash: crypto.SHA512,
	}
	if sig, err = privateKey.Sign(nil, prehash[:], opts); err != nil {
		panic("ed25519.SignWithOptions(ph): " + err.Error())
	}
	if !ed25519.VerifyWithOptions(publicKey, prehash[:], sig, opts) {
		panic("ed25519.VerifyWithOptions(ph): failed")
	}

	fmt.Println("ok")
	// Output: ok
}
