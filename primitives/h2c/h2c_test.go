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

package h2c

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/internal/elligator"
	"github.com/oasisprotocol/curve25519-voi/internal/field"
)

type hashToCurveTestVector struct {
	msg  string
	x, y string
}

func (vec *hashToCurveTestVector) ToCoordinates() (*field.Element, *field.Element, error) {
	x, err := hex.DecodeString(vec.x)
	if err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize P.x: %w", err)
	}
	y, err := hex.DecodeString(vec.y)
	if err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize P.y: %w", err)
	}

	// The IETF test vectors provide all coordinates in big-endian byte order.
	x = reversedByteSlice(x)
	y = reversedByteSlice(y)

	// Generate a point from the test vector x and y-coordinates.
	var feX, feY field.Element
	if _, err = feX.SetBytes(x); err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize x: %w", err)
	}
	if _, err = feY.SetBytes(y); err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize y: %w", err)
	}

	return &feX, &feY, nil
}

func (vec *hashToCurveTestVector) ToEdwardsPoint() (*curve.EdwardsPoint, error) {
	feX, feY, err := vec.ToCoordinates()
	if err != nil {
		return nil, err
	}

	var p curve.EdwardsPoint
	elligator.SetEdwardsFromXY(&p, feX, feY)

	return &p, nil
}

func TestHashToCurve(t *testing.T) {
	t.Run("edwards25519", func(t *testing.T) {
		checkEdwards := func(t *testing.T, dst []byte, vecs []hashToCurveTestVector, isRO bool) {
			for i, vec := range vecs {
				expected, err := vec.ToEdwardsPoint()
				if err != nil {
					t.Fatalf("failed to deserialize test vector[%d]: %v", i, err)
				}

				var p *curve.EdwardsPoint
				if isRO {
					p, err = Edwards25519_XMD_SHA512_ELL2_RO(dst, []byte(vec.msg))
				} else {
					p, err = Edwards25519_XMD_SHA512_ELL2_NU(dst, []byte(vec.msg))
				}
				if err != nil {
					t.Fatalf("h2c: failed to generate point[%d]: %v", i, err)
				}

				if expected.Equal(p) != 1 {
					var cp curve.CompressedEdwardsY
					cp.SetEdwardsPoint(p)
					t.Fatalf("h2c: point[%d] mismatch (Got: '%x')", i, cp[:])
				}
			}
		}

		t.Run("XMD:SHA512_ELL2_RO_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6",
					y:   "09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",
				},
				{
					msg: "abc",
					x:   "608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad",
					y:   "1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",
				},
				{
					msg: "abcdef0123456789",
					x:   "6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472",
					y:   "53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "5fb0b92acedd16f3bcb0ef83f5c7b7a9466b5f1e0d8d217421878ea3686f8524",
					y:   "2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "0efcfde5898a839b00997fbe40d2ebe950bc81181afbd5cd6b9618aa336c1e8c",
					y:   "6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995",
				},
			}

			checkEdwards(t, dst, vecs, true)
		})
		t.Run("XMD:SHA512_ELL2_NU_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "1ff2b70ecf862799e11b7ae744e3489aa058ce805dd323a936375a84695e76da",
					y:   "222e314d04a4d5725e9f2aff9fb2a6b69ef375a1214eb19021ceab2d687f0f9b",
				},

				{
					msg: "abc",
					x:   "5f13cc69c891d86927eb37bd4afc6672360007c63f68a33ab423a3aa040fd2a8",
					y:   "67732d50f9a26f73111dd1ed5dba225614e538599db58ba30aaea1f5c827fa42",
				},
				{
					msg: "abcdef0123456789",
					x:   "1dd2fefce934ecfd7aae6ec998de088d7dd03316aa1847198aecf699ba6613f1",
					y:   "2f8a6c24dd1adde73909cada6a4a137577b0f179d336685c4a955a0a8e1a86fb",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "35fbdc5143e8a97afd3096f2b843e07df72e15bfca2eaf6879bf97c5d3362f73",
					y:   "2af6ff6ef5ebba128b0774f4296cb4c2279a074658b083b8dcca91f57a603450",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "6e5e1f37e99345887fc12111575fc1c3e36df4b289b8759d23af14d774b66bff",
					y:   "2c90c3d39eb18ff291d33441b35f3262cdd307162cc97c31bfcc7a4245891a37",
				},
			}

			checkEdwards(t, dst, vecs, false)
		})
	})
}
