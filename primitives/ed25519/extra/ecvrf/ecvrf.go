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

// Package ecvrf implements the "Verifiable Random Functions (VRFs)"
// IETF draft, providing the ECVRF-EDWARDS25519-SHA512-ELL2 suite.
package ecvrf

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/h2c"
)

const (
	// ProofSize is the size, in bytes, of proofs as used in this package.
	ProofSize = 80

	// OutputSize is the size, in bytes, of outputs as used in this package.
	OutputSize = 64

	zeroString  = 0x00
	twoString   = 0x02
	threeString = 0x03
	suiteString = 0x04

	addedRandomnessSize = 32
)

var (
	// The domain separation tag DST, a parameter to the hash-to-curve
	// suite, SHALL be set to "ECVRF_" || h2c_suite_ID_string || suite_string
	h2cDST = []byte{
		'E', 'C', 'V', 'R', 'F', '_', // "ECVRF_"
		'e', 'd', 'w', 'a', 'r', 'd', 's', '2', '5', '5', '1', '9', '_', 'X', 'M', 'D', ':', 'S', 'H', 'A', '-', '5', '1', '2', '_', 'E', 'L', 'L', '2', '_', 'N', 'U', '_', // h2c_suite_ID_string
		suiteString, // suite_string
	}

	addedRandomnessPadding [1024]byte
)

// Prove implements ECVRF_prove for the suite ECVRF-EDWARDS25519-SHA512-ELL2.
func Prove(sk ed25519.PrivateKey, alphaString []byte) []byte {
	piString, err := doProve(nil, sk, alphaString)
	if err != nil {
		panic(err)
	}
	return piString
}

// ProveWithAddedRandomness implements ECVRF_prove for the suite ECVRF-EDWARDS25519-SHA512-ELL2,
// while including additional randomness to mitigate certain fault injection
// and side-channel attacks.  If rand is nil, crypto/rand.Reader will be used.
//
// Warning: If this is set, proofs (`beta_string`) will be non-deterministic.
// The VRF output (`pi_string`) is identical to that produced by Prove.
func ProveWithAddedRandomness(rand io.Reader, sk ed25519.PrivateKey, alphaString []byte) ([]byte, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	return doProve(rand, sk, alphaString)
}

func doProve(rand io.Reader, sk ed25519.PrivateKey, alphaString []byte) ([]byte, error) {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF
	// public key Y = x*B (this derivation depends on the ciphersuite,
	// as per Section 5.5; these values can be cached, for example,
	// after key generation, and need not be rederived each time)

	if len(sk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ecvrf: bad private key length")
	}

	var (
		extsk [64]byte
		x     scalar.Scalar
	)
	h := sha512.New()
	_, _ = h.Write(sk[:32])
	h.Sum(extsk[:0])
	extsk[0] &= 248
	extsk[31] &= 127
	extsk[31] |= 64
	if _, err := x.SetBits(extsk[:32]); err != nil {
		return nil, fmt.Errorf("ecvrf: failed to deserialize x scalar: %w", err)
	}
	Y := sk[32:]

	// 2.  H = ECVRF_hash_to_curve(Y, alpha_string)
	H, err := hashToCurveH2cSuite(Y, alphaString)
	if err != nil {
		return nil, fmt.Errorf("ecvrf: failed to hash point to curve: %w", err)
	}

	// 3.  h_string = point_to_string(H)
	var hString curve.CompressedEdwardsY
	hString.SetEdwardsPoint(H)

	// 4.  Gamma = x*H
	var (
		gamma       curve.EdwardsPoint
		gammaString curve.CompressedEdwardsY
	)
	gamma.Mul(H, &x)
	gammaString.SetEdwardsPoint(&gamma)

	// 5.  k = ECVRF_nonce_generation(SK, h_string)
	var (
		digest [64]byte
		k      scalar.Scalar
	)
	h.Reset()
	if rand != nil {
		var entropy [addedRandomnessSize]byte
		if _, err := io.ReadFull(rand, entropy[:]); err != nil {
			return nil, fmt.Errorf("ecvrf: failed to read Z: %w", err)
		}
		_, _ = h.Write(entropy[:])
	}
	_, _ = h.Write(extsk[32:])
	if rand != nil {
		padSize := len(addedRandomnessPadding) - (addedRandomnessSize + 32)
		_, _ = h.Write(addedRandomnessPadding[:padSize])
	}
	_, _ = h.Write(hString[:])
	h.Sum(digest[:0])
	if _, err = k.SetBytesModOrderWide(digest[:]); err != nil {
		return nil, fmt.Errorf("ecvrf: failed to deserialize k scalar: %w", err)
	}

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H) (see Section 5.4.3)
	var kB, kH curve.EdwardsPoint
	kB.MulBasepoint(curve.ED25519_BASEPOINT_TABLE, &k)
	kH.Mul(H, &k)
	c := hashPoints(&hString, &gammaString, &kB, &kH)

	// 7.  s = (k + c*x) mod q
	var s scalar.Scalar
	s.Mul(c, &x)
	s.Add(&s, &k)

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) ||
	//                 int_to_string(s, qLen)
	var piString [ProofSize]byte
	copy(piString[:32], gammaString[:])
	if err = c.ToBytes(piString[32:64]); err != nil {
		return nil, fmt.Errorf("ecvrf: failed to serialize c scalar: %w", err)
	}
	if err = s.ToBytes(piString[48:]); err != nil { // c is truncated (128-bits).
		return nil, fmt.Errorf("ecvrf: failed to serialize s scalar: %w", err)
	}

	// 9.  Output pi_string
	return piString[:], nil
}

// ProofToHash implements ECVRF_proof_to_hash for the suite ECVRF-EDWARDS25519-SHA512-ELL2,
// in variable-time.
//
// ECVRF_proof_to_hash should be run only on pi_string that is known
// to have been produced by ECVRF_prove, or from within ECVRF_verify.
func ProofToHash(piString []byte) ([]byte, error) {
	// 1.  D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
	// 2.  If D is "INVALID", output "INVALID" and stop
	// 3.  (Gamma, c, s) = D
	gamma, _, _, err := decodeProof(piString)
	if err != nil {
		return nil, fmt.Errorf("ecvrf: failed to decode proof: %w", err)
	}

	// Steps 4 .. 7 are in gammaToHash.
	return gammaToHash(gamma), nil
}

// Verify implements ECVRF_verify for the suite ECVRF-EDWARDS25519-SHA512-ELL2.
//
// The public key is validated such that the "full uniqueness" and
// "full collision" properties are satisfied.
func Verify(pk ed25519.PublicKey, piString, alphaString []byte) (bool, []byte) {
	// 1.  D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
	// 2.  If D is "INVALID", output "INVALID" and stop
	// 3.  (Gamma, c, s) = D
	gamma, c, s, err := decodeProof(piString)
	if err != nil {
		return false, nil
	}
	var gammaString curve.CompressedEdwardsY
	_, _ = gammaString.SetBytes(piString[:32])

	// 4.  H = ECVRF_hash_to_curve(Y, alpha_string)
	var (
		Y       curve.EdwardsPoint
		yString curve.CompressedEdwardsY
	)
	if _, err := yString.SetBytes(pk); err != nil {
		return false, nil
	}
	if !yString.IsCanonicalVartime() { // Required by RFC 8032 decode semantics.
		return false, nil
	}
	if _, err := Y.SetCompressedY(&yString); err != nil {
		return false, nil
	}
	if Y.IsSmallOrder() { // Section 5.6.1 ECVRF Validate Key
		return false, nil
	}
	H, err := hashToCurveH2cSuite(yString[:], alphaString)
	if err != nil {
		panic("ecvrf: failed to hash point to curve: " + err.Error())
	}
	var hString curve.CompressedEdwardsY
	hString.SetEdwardsPoint(H)

	// 5.  U = s*B - c*Y
	var U curve.EdwardsPoint
	Y.Neg(&Y)
	U.DoubleScalarMulBasepointVartime(c, &Y, s)

	// 6.  V = s*H - c*Gamma
	var V, negGamma curve.EdwardsPoint
	negGamma.Neg(gamma)
	V.MultiscalarMulVartime( // V = s*H + c*(-Gamma)
		[]*scalar.Scalar{s, c},
		[]*curve.EdwardsPoint{H, &negGamma},
	)

	// 7.  c' = ECVRF_hash_points(H, Gamma, U, V) (see Section 5.4.3)
	cPrime := hashPoints(&hString, &gammaString, &U, &V)

	// 8.  If c and c' are equal, output ("VALID",
	//     ECVRF_proof_to_hash(pi_string)); else output "INVALID"
	if c.Equal(cPrime) == 0 {
		return false, nil
	}
	return true, gammaToHash(gamma)
}

func gammaToHash(gamma *curve.EdwardsPoint) []byte {
	// 4.  three_string = 0x03 = int_to_string(3, 1), a single octet with
	//     value 3
	// 5.  zero_string = 0x00 = int_to_string(0, 1), a single octet with
	//     value 0
	// 6.  beta_string = Hash(suite_string || three_string ||
	//     point_to_string(cofactor * Gamma) || zero_string)
	// 7.  Output beta_string
	var (
		cG       curve.EdwardsPoint
		cGString curve.CompressedEdwardsY
	)
	cGString.SetEdwardsPoint(cG.MulByCofactor(gamma))
	h := sha512.New()
	_, _ = h.Write([]byte{suiteString, threeString}) // suite_string, three_string
	_, _ = h.Write(cGString[:])                      // point_to_string(cofactor * Gamma)
	_, _ = h.Write([]byte{zeroString})               // zero_string
	return h.Sum(nil)
}

func hashToCurveH2cSuite(Y, alphaString []byte) (*curve.EdwardsPoint, error) {
	// 1.  PK_string = point_to_string(Y)
	// 2.  string_to_hash = PK_string || alpha_string
	stringToHash := make([]byte, 0, len(Y)+len(alphaString))
	stringToHash = append(stringToHash, Y...)
	stringToHash = append(stringToHash, alphaString...)

	// 3.  H = encode(string_to_hash)
	// 4.  Output H
	return h2c.Edwards25519_XMD_SHA512_ELL2_NU(h2cDST, stringToHash)
}

func hashPoints(p1, p2 *curve.CompressedEdwardsY, p3, p4 *curve.EdwardsPoint) *scalar.Scalar {
	// 1.  two_string = 0x02 = int_to_string(2, 1), a single octet with
	//     value 2
	// 2.  Initialize str = suite_string || two_string
	// 3.  for PJ in [P1, P2, ... PM]:
	//       str = str || point_to_string(PJ)
	// 4.  zero_string = 0x00 = int_to_string(0, 1), a single octet with
	//     value 0
	// 5.  str = str || zero_string
	// 6.  c_string = Hash(str)
	var (
		tmp    curve.CompressedEdwardsY
		digest [64]byte
	)
	h := sha512.New()
	_, _ = h.Write([]byte{suiteString, twoString}) // suite_string || two_string
	_, _ = h.Write(p1[:])                          // point_to_string(P1)
	_, _ = h.Write(p2[:])                          // point_to_string(P2)
	_, _ = h.Write(tmp.SetEdwardsPoint(p3)[:])     // point_to_string(P3)
	_, _ = h.Write(tmp.SetEdwardsPoint(p4)[:])     // point_to_string(P4)
	_, _ = h.Write([]byte{zeroString})             // zero_string
	h.Sum(digest[:0])

	// 7.  truncated_c_string = c_string[0]...c_string[n-1]
	// 8.  c = string_to_int(truncated_c_string)
	var (
		cString [scalar.ScalarSize]byte
		c       scalar.Scalar
	)
	copy(cString[:16], digest[:16])
	if _, err := c.SetBits(cString[:]); err != nil {
		panic("ecvrf: failed to deserialize c scalar: " + err.Error())
	}

	// 9.  Output c
	return &c
}

func decodeProof(piString []byte) (*curve.EdwardsPoint, *scalar.Scalar, *scalar.Scalar, error) {
	if l := len(piString); l != ProofSize {
		return nil, nil, nil, fmt.Errorf("ecvrf: invalid proof size: %d", l)
	}

	// 1.  let gamma_string = pi_string[0]...pi_string[ptLen-1]
	// 2.  let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
	// 3.  let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]

	// 4.  Gamma = string_to_point(gamma_string)
	// 5.  if Gamma = "INVALID" output "INVALID" and stop.
	var gammaString curve.CompressedEdwardsY
	if _, err := gammaString.SetBytes(piString[:32]); err != nil {
		// Should *NEVER* happen.
		panic("ecvrf: failed to copy gamma_string: " + err.Error())
	}
	if !gammaString.IsCanonicalVartime() { // Required by RFC 8032 decode semantics.
		return nil, nil, nil, fmt.Errorf("ecvrf: non-canonical gamma")
	}
	var gamma curve.EdwardsPoint
	if _, err := gamma.SetCompressedY(&gammaString); err != nil {
		return nil, nil, nil, fmt.Errorf("ecvrf: failed to decompress gamma: %w", err)
	}

	// 6.  c = string_to_int(c_string)
	var (
		cString [scalar.ScalarSize]byte
		c       scalar.Scalar
	)
	copy(cString[:16], piString[32:])
	if _, err := c.SetBits(cString[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("ecvrf: failed to deserialize c scalar: %w", err)
	}

	// 7.  s = string_to_int(s_string)
	// 8.  if s >= q output "INVALID" and stop
	var s scalar.Scalar
	if !scalar.ScMinimalVartime(piString[48:]) {
		return nil, nil, nil, fmt.Errorf("ecvrf: non-canonical s")
	}
	if _, err := s.SetBytesModOrder(piString[48:]); err != nil {
		return nil, nil, nil, fmt.Errorf("ecvrf: failed to deserialize s scalar: %w", err)
	}

	// 8.  Output Gamma, c, and s
	return &gamma, &c, &s, nil
}
