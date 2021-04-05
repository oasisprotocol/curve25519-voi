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

// Package slip0010 implements the SLIP-0010 private key derivation
// scheme for Ed25519.
package slip0010

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

const (
	// SeedSize is the BIP-0039 seed byte sequence size in bytes.
	SeedSize = 64

	// ChainCodeSize is the size of a SLIP-0010 chain code in bytes.
	ChainCodeSize = 32
)

var curveConstant = []byte("ed25519 seed")

// ChainCode is a SLIP-0010 chain code.
type ChainCode [ChainCodeSize]byte

// NewMasterKey derives a master key and chain code from a seed byte sequence.
func NewMasterKey(seed []byte) (ed25519.PrivateKey, ChainCode, error) {
	// 1. Generate a seed byte sequence S of 512 bits according to BIP-0039.
	if len(seed) != SeedSize {
		return nil, ChainCode{}, fmt.Errorf("slip0010: invalid seed")
	}

	// 2. Calculate I = HMAC-SHA512(Key = Curve, Data = S)
	mac := hmac.New(sha512.New, curveConstant)
	_, _ = mac.Write(seed)
	I := mac.Sum(nil)

	// 3. Split I into two 32-byte sequences, IL and IR.
	// 4. Use parse256(IL) as master secret key, and IR as master chain code.
	return splitDigest(I)
}

// NewChildKey derives a child key and chain code from a (parent key,
// parent chain code, index) tuple.
func NewChildKey(kPar ed25519.PrivateKey, cPar ChainCode, index uint32) (ed25519.PrivateKey, ChainCode, error) {
	if len(kPar) != ed25519.PrivateKeySize {
		return nil, ChainCode{}, fmt.Errorf("slip0010: invalid parent key")
	}

	// 1. Check whether i >= 2^31 (whether the child is a hardened key).
	if index < 1<<31 {
		// If not (normal child):
		// If curve is ed25519: return failure.
		return nil, ChainCode{}, fmt.Errorf("slip0010: non-hardened keys not supported")
	}

	// If so (hardened child):
	// let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
	// (Note: The 0x00 pads the private key to make it 33 bytes long.)
	var b [4]byte
	mac := hmac.New(sha512.New, cPar[:])
	_, _ = mac.Write(b[0:1])                // 0x00
	_, _ = mac.Write(kPar.Seed())           // ser256(kPar)
	binary.BigEndian.PutUint32(b[:], index) // Note: The spec neglects to define ser32.
	_, _ = mac.Write(b[:])                  // ser32(i)
	I := mac.Sum(nil)

	// 2. Split I into two 32-byte sequences, IL and IR.
	// 3. The returned chain code ci is IR.
	// 4. If curve is ed25519: The returned child key ki is parse256(IL).
	return splitDigest(I)
}

func splitDigest(digest []byte) (ed25519.PrivateKey, ChainCode, error) {
	IL, IR := digest[:32], digest[32:]

	var chainCode ChainCode
	privKey := ed25519.NewKeyFromSeed(IL)
	copy(chainCode[:], IR)

	return privKey, chainCode, nil
}
