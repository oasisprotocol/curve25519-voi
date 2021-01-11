// Copyright (c) 2019 Oglev Andreev. All rights reserved.
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

package curve

import "github.com/oasisprotocol/curve25519-voi/curve/scalar"

func (p *EdwardsPoint) multiscalarMulPippengerVartime(scalars []*scalar.Scalar, points []*EdwardsPoint) {
	size := len(scalars)

	// Digit width in bits. As digit width grows,
	// number of point additions goes down, but amount of
	// buckets and bucket additions grows exponentially.
	var w uint
	switch {
	case size < 500:
		w = 6
	case size < 800:
		w = 7
	default:
		w = 8
	}

	maxDigit := 1 << w
	digitsCount := scalar.ToRadix2wSizeHint(w)
	bucketsCount := maxDigit / 2 // digits are signed+centered hence 2^w/2, excluding 0-th bucket.

	// Collect optimized scalars and points in buffers for repeated access
	// (scanning the whole set per digit position).
	optScalars := make([][43]int8, 0, size)
	for _, scalar := range scalars {
		optScalars = append(optScalars, scalar.ToRadix2w(w))
	}

	optPoints := make([]projectiveNielsPoint, size)
	for i, point := range points {
		optPoints[i].fromEdwards(point)
	}

	// Prepare 2^w/2 buckets.
	// buckets[i] corresponds to a multiplication factor (i+1).
	buckets := make([]EdwardsPoint, bucketsCount)
	for i := range buckets {
		buckets[i].Identity()
	}

	// TODO/perf: Compared to using an interator this results in 1 more
	// allocation, that should probably be eliminated.
	var tmp completedPoint
	columns := make([]EdwardsPoint, digitsCount)
	for idx := int(digitsCount - 1); idx >= 0; idx-- {
		// Clear the buckets when processing another digit.
		for i := 0; i < bucketsCount; i++ {
			buckets[i].Identity()
		}

		// Iterate over pairs of (point, scalar)
		// and add/sub the point to the corresponding bucket.
		// Note: if we add support for precomputed lookup tables,
		// we'll be adding/subtracting point premultiplied by `digits[i]` to buckets[0].
		for i := 0; i < size; i++ {
			digit := int16(optScalars[i][idx])
			if digit > 0 {
				b := uint(digit - 1)
				tmp.addEdwardsProjectiveNiels(&buckets[b], &optPoints[i])
				buckets[b].fromCompleted(&tmp)
			} else if digit < 0 {
				b := uint(-digit - 1)
				tmp.subEdwardsProjectiveNiels(&buckets[b], &optPoints[i])
				buckets[b].fromCompleted(&tmp)
			}
		}

		// Add the buckets applying the multiplication factor to each bucket.
		// The most efficient way to do that is to have a single sum with two running sums:
		// an intermediate sum from last bucket to the first, and a sum of intermediate sums.
		//
		// For example, to add buckets 1*A, 2*B, 3*C we need to add these points:
		//   C
		//   C B
		//   C B A   Sum = C + (C+B) + (C+B+A)

		bucketsIntermediateSum := buckets[bucketsCount-1]
		bucketsSum := buckets[bucketsCount-1]
		for i := int((bucketsCount - 1) - 1); i >= 0; i-- {
			bucketsIntermediateSum.Add(&bucketsIntermediateSum, &buckets[i])
			bucketsSum.Add(&bucketsSum, &bucketsIntermediateSum)
		}

		columns[idx] = bucketsSum
	}

	// Take the high column as an initial value to avoid wasting time doubling
	// the identity element.
	sum := columns[digitsCount-1]
	for i := int(digitsCount-1) - 1; i >= 0; i-- {
		sumMul := sum
		sumMul.mulByPow2(w)
		sum.Add(&sumMul, &columns[i])
	}

	*p = sum
}
