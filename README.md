### curve25519-voi

> It was only machinery.  I’m surprised it’s lasted as long as it has,
> frankly.  There must still be some residual damage-repair capability.
> We Demarchists build for posterity, you know.

This package aims to provide a modern X25519/Ed25519 implementation
for Go, mostly derived from curve25519-dalek.  The primary motivation
is to hopefully provide a worthy alternative to the current state of
available Go implementations, which is best described as "a gigantic
mess of ref10 and donna ports".  The irony of the previous statement
in the light of curve25519-dalek's lineage does not escape this author.

#### WARNING

***DO NOT BOTHER THE curve25519-dalek DEVELOPERS ABOUT THIS PACKAGE***

This package has yet to be reviewed.  Use something else.

#### Package structure

 * curve: A mid-level API in the spirit of curve25519-dalek.
 * primitives/x25519: A X25519 implementation like `x/crypto/curve25519`.
 * primitives/ed25519: A Ed25519 implementation like `crypto/ed25519`.

#### Ed25519 verification semantics

At the time of this writing, Ed25519 signature verification behavior
varies based on the implementation.  The implementation provided by
this package aims to provide a sensible default, and to support
compatibility with other implementations if required.

The default verification semantics are as follows, using the terminology
from [ed25519-speccheck][1]:

 * Both iterative and batch verification are cofactored.
 * Small order A is rejected.
 * Small order R is accepted.
 * Non-canonical A is rejected.
 * Non-canonical R is rejected.
 * A signature's scalar component must be in canonical form (S < L).

Pre-defined configuration presets for compatibility with the Go standard
library, FIPS 186-5/RFC 8032, and ZIP-215 are provided for convenience.

For more details on this general problem, see [Taming the many EdDSAs][2].

#### Performance

All measurements were taken on an Intel(R) Core(TM) i7-10510U @ 1.80GHz
with turbo disabled, using Go 1.16.2 as the toolchain.  As there are
multiple definitions of "Ed25519 signature verification", curve25519-voi
was configured for each benchmark to use as similar verification semantics
as possible.

| Implementation      | Version/Commit                           |
| ------------------- | ---------------------------------------- |
| crypto/ed25519      | 1.16.2                                   |
| x/crypto/curve25519 | 0c34fe9e7dc2486962ef9867e3edb3503537209f |
| circl               | 3977848c88c641772e447c63a0ec29c8f4085e58 |
| ed25519consensus    | 59a8610d2b877a977e021f711e382bc0e757bf48 |
| curve25519-voi      | 02fcc67acb4eb914bc7485d991446bab53adb0dd |

##### Native

```
name \ time/op            stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult     80.9µs ± 1%    44.1µs ± 0%                    27.5µs ± 1%
X25519/ScalarMult         80.4µs ± 0%    65.4µs ± 1%                    80.5µs ± 0%
Ed25519/NewKeyFromSeed     105µs ± 1%      55µs ± 1%                      28µs ± 0%
Ed25519/Sign               109µs ± 0%      58µs ± 0%                      31µs ± 1%
Ed25519/Verify             296µs ± 1%     125µs ± 1%                      89µs ± 0%
Ed25519/Verify_ZIP215                                       137µs ± 0%    79µs ± 0%
Ed25519/VerifyBatch_1                                       173µs ± 2%   114µs ± 1%
Ed25519/VerifyBatch_8                                       606µs ± 1%   495µs ± 3%
Ed25519/VerifyBatch_16                                     1.10ms ± 0%  0.90ms ± 0%
Ed25519/VerifyBatch_32                                     2.09ms ± 0%  1.73ms ± 0%
Ed25519/VerifyBatch_64                                     4.07ms ± 0%  3.40ms ± 0%
Ed25519/VerifyBatch_128                                    8.05ms ± 1%  6.55ms ± 0%
Ed25519/VerifyBatch_256                                    16.1ms ± 0%  12.2ms ± 0%
Ed25519/VerifyBatch_512                                    32.3ms ± 0%  23.3ms ± 0%
Ed25519/VerifyBatch_1024                                   64.7ms ± 0%  44.5ms ± 0%

name \ alloc/op           stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00B          0.00B                          0.00B
X25519/ScalarMult          0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed     0.00B          0.00B                          0.00B
Ed25519/Sign               0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify             0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                       0.00B        0.00B
Ed25519/VerifyBatch_1                                      5.65kB ± 0%  5.46kB ± 0%
Ed25519/VerifyBatch_8                                      31.9kB ± 0%  34.0kB ± 0%
Ed25519/VerifyBatch_16                                     69.3kB ± 0%  65.9kB ± 0%
Ed25519/VerifyBatch_32                                      130kB ± 0%   138kB ± 0%
Ed25519/VerifyBatch_64                                      254kB ± 0%   267kB ± 0%
Ed25519/VerifyBatch_128                                     497kB ± 0%   353kB ± 0%
Ed25519/VerifyBatch_256                                     970kB ± 0%   701kB ± 0%
Ed25519/VerifyBatch_512                                    1.93MB ± 0%  1.40MB ± 0%
Ed25519/VerifyBatch_1024                                   3.82MB ± 0%  2.76MB ± 0%

name \ allocs/op          stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult       0.00           0.00                           0.00
X25519/ScalarMult           0.00           0.00                           0.00
Ed25519/NewKeyFromSeed      0.00           0.00                           0.00
Ed25519/Sign                0.00           4.00 ± 0%                      1.00 ± 0%
Ed25519/Verify              0.00          15.00 ± 0%                      0.00
Ed25519/Verify_ZIP215                                        0.00         0.00
Ed25519/VerifyBatch_1                                        9.00 ± 0%   12.00 ± 0%
Ed25519/VerifyBatch_8                                        26.0 ± 0%    29.0 ± 0%
Ed25519/VerifyBatch_16                                       43.0 ± 0%    46.0 ± 0%
Ed25519/VerifyBatch_32                                       76.0 ± 0%    79.0 ± 0%
Ed25519/VerifyBatch_64                                        141 ± 0%     144 ± 0%
Ed25519/VerifyBatch_128                                       270 ± 0%     273 ± 0%
Ed25519/VerifyBatch_256                                       527 ± 0%     530 ± 0%
Ed25519/VerifyBatch_512                                     1.04k ± 0%   1.04k ± 0%
Ed25519/VerifyBatch_1024                                    2.06k ± 0%   2.07k ± 0%
```

Notes:

 * On `amd64` systems, unless explicitly disabled curve25519-voi will
   use the x/crypto/curve25519 `ScalarMult` implementation, because there
   is no reason not to, and it is hand-optimized assembly language.

##### purego (Assembly optimizations disabled)

```
name \ time/op            stdlib      circl          ed25519consensus  voi
X25519/ScalarBaseMult     323µs ± 1%      73µs ± 1%                      56µs ± 0%
X25519/ScalarMult         323µs ± 1%     119µs ± 1%                     131µs ± 1%
Ed25519/NewKeyFromSeed    105µs ± 1%      67µs ± 0%                      56µs ± 1%
Ed25519/Sign              108µs ± 1%      69µs ± 1%                      60µs ± 0%
Ed25519/Verify            296µs ± 0%     146µs ± 0%                     139µs ± 0%
Ed25519/Verify_ZIP215                                      199µs ± 0%   116µs ± 1%
Ed25519/VerifyBatch_1                                      246µs ± 0%   185µs ± 0%
Ed25519/VerifyBatch_8                                      872µs ± 0%   723µs ± 1%
Ed25519/VerifyBatch_16                                    1.58ms ± 1%  1.32ms ± 0%
Ed25519/VerifyBatch_32                                    2.99ms ± 0%  2.51ms ± 0%
Ed25519/VerifyBatch_64                                    5.81ms ± 0%  4.92ms ± 0%
Ed25519/VerifyBatch_128                                   11.5ms ± 0%   9.9ms ± 0%
Ed25519/VerifyBatch_256                                   23.0ms ± 0%  18.0ms ± 0%
Ed25519/VerifyBatch_512                                   45.9ms ± 0%  33.5ms ± 1%
Ed25519/VerifyBatch_1024                                  91.9ms ± 0%  62.7ms ± 0%

name \ alloc/op           stdlib      circl          ed25519consensus  voi
X25519/ScalarBaseMult     0.00B          0.00B                          0.00B
X25519/ScalarMult         0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed    0.00B          0.00B                          0.00B
Ed25519/Sign              0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify            0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                      0.00B        0.00B
Ed25519/VerifyBatch_1                                     5.65kB ± 0%  5.46kB ± 0%
Ed25519/VerifyBatch_8                                     31.9kB ± 0%  34.0kB ± 0%
Ed25519/VerifyBatch_16                                    69.3kB ± 0%  65.9kB ± 0%
Ed25519/VerifyBatch_32                                     130kB ± 0%   138kB ± 0%
Ed25519/VerifyBatch_64                                     254kB ± 0%   267kB ± 0%
Ed25519/VerifyBatch_128                                    497kB ± 0%   353kB ± 0%
Ed25519/VerifyBatch_256                                    970kB ± 0%   701kB ± 0%
Ed25519/VerifyBatch_512                                   1.93MB ± 0%  1.40MB ± 0%
Ed25519/VerifyBatch_1024                                  3.82MB ± 0%  2.76MB ± 0%

name \ allocs/op          stdlib      circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00           0.00                           0.00
X25519/ScalarMult          0.00           0.00                           0.00
Ed25519/NewKeyFromSeed     0.00           0.00                           0.00
Ed25519/Sign               0.00           4.00 ± 0%                      1.00 ± 0%
Ed25519/Verify             0.00          15.00 ± 0%                      0.00
Ed25519/Verify_ZIP215                                       0.00         0.00
Ed25519/VerifyBatch_1                                       9.00 ± 0%   12.00 ± 0%
Ed25519/VerifyBatch_8                                       26.0 ± 0%    29.0 ± 0%
Ed25519/VerifyBatch_16                                      43.0 ± 0%    46.0 ± 0%
Ed25519/VerifyBatch_32                                      76.0 ± 0%    79.0 ± 0%
Ed25519/VerifyBatch_64                                       141 ± 0%     144 ± 0%
Ed25519/VerifyBatch_128                                      270 ± 0%     273 ± 0%
Ed25519/VerifyBatch_256                                      527 ± 0%     530 ± 0%
Ed25519/VerifyBatch_512                                    1.04k ± 0%   1.04k ± 0%
Ed25519/VerifyBatch_1024                                   2.06k ± 0%   2.07k ± 0%
```

##### Precomputed verification

curve25519-voi supports expanding public keys, to accelerate repeated
Ed25519 signature verification with the same public key.  This will be a
net performance gain if a public key will be used to verify signatures
more than once, and costs approximately 1.47 KiB of memory per public key.

The batch verification code is written under the assumption that batches
consisting primarily/entirely of expanded keys is the common case (and in
fact will convert non-expanded public keys to expanded form internally).

```
name                      old time/op    new time/op    delta
Ed25519/NewExpandedPublicKey               13.5µs ± 1%
Ed25519/Verify              88.9µs ± 0%    77.3µs ± 1%  -13.04%  (p=0.008 n=5+5)
Ed25519/Verify_ZIP215       79.4µs ± 0%    66.5µs ± 0%  -16.28%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1        114µs ± 1%     101µs ± 1%  -11.67%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8        495µs ± 3%     377µs ± 2%  -23.74%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16       902µs ± 0%     680µs ± 0%  -24.57%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32      1.73ms ± 0%    1.29ms ± 0%  -25.55%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64      3.40ms ± 0%    2.52ms ± 1%  -25.94%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128     6.55ms ± 0%    4.82ms ± 0%  -26.39%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256     12.2ms ± 0%     8.8ms ± 1%  -28.07%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512     23.3ms ± 0%    16.4ms ± 0%  -29.77%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024    44.5ms ± 0%    30.5ms ± 0%  -31.44%  (p=0.008 n=5+5)

name                      old alloc/op   new alloc/op   delta
Ed25519/NewExpandedPublicKey               1.50kB ± 0%
Ed25519/Verify               0.00B          0.00B          ~     (all equal)
Ed25519/Verify_ZIP215        0.00B          0.00B          ~     (all equal)
Ed25519/VerifyBatch_1       5.46kB ± 0%    3.96kB ± 0%  -27.53%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8       34.0kB ± 0%    22.0kB ± 0%  -35.40%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16      65.9kB ± 0%    41.8kB ± 0%  -36.53%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32       138kB ± 0%      89kB ± 0%  -34.98%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64       267kB ± 0%     171kB ± 0%  -36.07%  (p=0.000 n=5+4)
Ed25519/VerifyBatch_128      353kB ± 0%     161kB ± 0%  -54.49%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256      701kB ± 0%     316kB ± 0%  -54.96%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512     1.40MB ± 0%    0.63MB ± 0%  -55.00%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024    2.76MB ± 0%    1.22MB ± 0%  -55.86%  (p=0.000 n=4+5)

name                      old allocs/op  new allocs/op  delta
Ed25519/NewExpandedPublicKey                 2.00 ± 0%
Ed25519/Verify                0.00           0.00          ~     (all equal)
Ed25519/Verify_ZIP215         0.00           0.00          ~     (all equal)
Ed25519/VerifyBatch_1         12.0 ± 0%      10.0 ± 0%  -16.67%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8         29.0 ± 0%      13.0 ± 0%  -55.17%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16        46.0 ± 0%      14.0 ± 0%  -69.57%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32        79.0 ± 0%      15.0 ± 0%  -81.01%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64         144 ± 0%        16 ± 0%  -88.89%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128        273 ± 0%        17 ± 0%  -93.77%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256        530 ± 0%        18 ± 0%  -96.60%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512      1.04k ± 0%     0.02k ± 0%  -98.18%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024     2.07k ± 0%     0.02k ± 0%  -99.03%  (p=0.008 n=5+5)
```

#### Notes

The curve25519-dalek crate makes use of "modern" programing language
features not available in Go.  This package's mid-level API attempts
to provide something usable by developers familiar with idiomatic Go,
and thus has more sharp edges, but in all honestly, developers that
opt to use the mid-level API in theory already know what they are
getting into.  Stability of the mid-level API is currently NOT
guaranteed.

The curve25519-dalek crate has a series of nice vectorized backends
written using SIMD intrinsics.  While Go has no SIMD intrinsics, and
the assembly dialect is anything but nice, the AVX2 backend is also
present in this implementation.

Memory sanitization while maintaining reasonable performance in Go is
a hard/unsolved problem, and this package makes no attempts to do so.
Anyone that mentions memguard will be asked to re-read the previous
sentence again, and then be mercilessly mocked.  It is worth noting
that the standard library does not do this appropriately either.

This package uses hand-crafted build tags of doom to determine if
the 32-bit or 64-bit codepath should be used, when both exist.

 * `amd64` will always use the 64-bit code.
 * `arm64`, `ppc64le`, `ppc64` will use the 64-bit code iff Go >= 1.13,
   32-bit otherwise.
 * `s390x` will use the 64-bit code iff Go >= 1.14, 32-bit otherwise.
 * `386`, `arm`, `mips`, `mipsle`, `mips64` will always use the 32-bit code.
 * All other `GOARCH`s are not supported.

This decision is more complicated than it should due to:

 * Go prior to 1.13 providing no guarantee regarding the timing
   characteristics of the `math/bits` intrinsics used by this package.
 * `math/bits.Mul64` and `math/bits.Add64` requiring special cases in
   the SSA code (`cmd/compile/internal/gc/ssa.go`) to be performant.
 * The Go developers rejecting [adding build tags for bit-width][3].

The lattice reduction implementation currently only has a 64-bit
version, and thus it will be used on all platforms.  This effectively
pegs the minimum required Go version at 1.12 due to the use of
`math/bits` intrinsics (as the lattice reduction is only done during
verification, the lack of a timing guarantee in that version has no
security impact).

#### Special credits

curve25519-voi would not exist if it were not for the amazing work
done by various other projects.  Any bugs in curve25519-voi are the
fault of the curve25519-voi developers alone.

 * The majority of curve25519-voi is derived from curve25519-dalek.

 * The Ed25519 batch verification started off as a port of the
   implementation present in ed25519-dalek, but was later switched
   to be based off ed25519consensus.

 * The ABGLSV-Pornin multiplication implementation is derived from
   a curve25519-dalek pull request by Jack Grigg (@str4d), with
   additional inspiration taken from Thomas Pornin's paper and
   curve9767 implementation.

 * The assembly optimized field element multiplications were taken
   (with minor modifications) from George Tankersley's ristretto255
   package.

[1]: https://github.com/novifinancial/ed25519-speccheck
[2]: https://eprint.iacr.org/2020/1244.pdf
[3]: https://github.com/golang/go/issues/33388
