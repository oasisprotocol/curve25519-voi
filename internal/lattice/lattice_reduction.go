// Copyright (c) 2020 Jack Grigg.  All rights reserved.
// Copyright (c) 2021 Oasis Labs Inc.  All rights reserved.
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

package lattice

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

var constELL_LOWER_HALF = newInt128(0x14def9dea2f79cd6, 0x5812631a5cf5d3ed)

// FindShortVector finds a "short" non-zero vector `(d_0, d_1)` such that
// `d_0 = d_1 k mod ell`. `d_0` and `d_1` may be negative.
//
// Implements Algorithm 4 from [Pornin 2020](https://eprint.iacr.org/2020/454).
func FindShortVector(k *scalar.Scalar) (Int128, Int128) {
	N_u := ellSquared()

	N_v := (&int512{}).Mul(k, k)
	N_v = N_v.Add(N_v, i512One)

	p := (&int512{}).Mul(scalar.BASEPOINT_ORDER, k)

	// The target bit-length of `N_v` for the vector to be considered short.
	const T = 254 // len(ell) + 1

	u_0, u_1 := constELL_LOWER_HALF, i128Zero
	v_0, v_1 := newInt128FromScalar(k), i128One

	for {
		if N_u.Cmp(N_v) == -1 { // N_u < N_v
			u_0, v_0 = v_0, u_0
			u_1, v_1 = v_1, u_1
			N_u, N_v = N_v, N_u
		}

		len_N_v := N_v.BitLen()
		if len_N_v <= T {
			return v_0, v_1
		}

		var s uint
		if len_p := p.BitLen(); len_p > len_N_v {
			s = len_p - len_N_v
		}

		var tmp int512
		if p.Cmp(i512Zero) == 1 { // p > 0
			u_0 = u_0.sub(v_0.shl(s))
			u_1 = u_1.sub(v_1.shl(s))

			N_u.Add(N_u, tmp.Shl(N_v, 2*s))
			N_u.Sub(N_u, tmp.Shl(p, s+1))
			p.Sub(p, tmp.Shl(N_v, s))
		} else {
			u_0 = u_0.add(v_0.shl(s))
			u_1 = u_1.add(v_1.shl(s))

			N_u.Add(N_u, tmp.Shl(N_v, 2*s))
			N_u.Add(N_u, tmp.Shl(p, s+1))
			p.Add(p, tmp.Shl(N_v, s))
		}
	}
}
