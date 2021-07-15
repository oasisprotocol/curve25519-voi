### curve25519-voi performance

All measurements were taken on an Intel(R) Core(TM) i7-10510U @ 1.80GHz
with turbo disabled, using Go 1.17beta1 as the toolchain.  As there are
multiple definitions of "Ed25519 signature verification", curve25519-voi
was configured for each benchmark to use as similar verification semantics
as possible where relevant.

| Implementation      | Version/Commit                           |
| ------------------- | ---------------------------------------- |
| crypto/ed25519      | 1.17beta1                                |
| x/crypto/curve25519 | v0.0.0-20210616213533-5ff15b29337e       |
| circl               | v1.0.1-0.20210714232413-699e42f52a9e     |
| ed25519consensus    | v0.0.0-20210430192048-0962ce16b305       |
| curve25519-voi      | 1a13596f11812957a29ee7cba5d059cb64022111 |

##### Native

```
name \ time/op            stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      107µs ± 1%      44µs ± 0%                      25µs ± 0%
X25519/ScalarMult          107µs ± 0%      65µs ± 0%                     107µs ± 0%
Ed25519/NewKeyFromSeed    43.1µs ± 1%    54.2µs ± 0%                    25.4µs ± 0%
Ed25519/Sign              52.8µs ± 0%    56.6µs ± 0%                    28.7µs ± 0%
Ed25519/Verify             125µs ± 0%     121µs ± 0%                      82µs ± 1%
Ed25519/Verify_ZIP215                                       129µs ± 0%    74µs ± 1%
Ed25519/VerifyBatch_1                                       160µs ± 0%   105µs ± 0%
Ed25519/VerifyBatch_8                                       574µs ± 1%   404µs ± 0%
Ed25519/VerifyBatch_16                                     1.05ms ± 0%  0.75ms ± 0%
Ed25519/VerifyBatch_32                                     1.99ms ± 0%  1.42ms ± 0%
Ed25519/VerifyBatch_64                                     3.88ms ± 0%  2.79ms ± 0%
Ed25519/VerifyBatch_128                                    7.68ms ± 0%  5.39ms ± 1%
Ed25519/VerifyBatch_256                                    15.3ms ± 0%  10.1ms ± 4%
Ed25519/VerifyBatch_512                                    30.8ms ± 0%  19.1ms ± 0%
Ed25519/VerifyBatch_1024                                   62.0ms ± 1%  36.1ms ± 0%

name \ alloc/op           stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00B          0.00B                          0.00B
X25519/ScalarMult          0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed     0.00B          0.00B                          0.00B
Ed25519/Sign               0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify             0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                       0.00B        0.00B
Ed25519/VerifyBatch_1                                      5.65kB ± 0%  5.43kB ± 0%
Ed25519/VerifyBatch_8                                      31.9kB ± 0%  34.0kB ± 0%
Ed25519/VerifyBatch_16                                     69.3kB ± 0%  65.8kB ± 0%
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
   use the x/crypto/curve25519 `ScalarMult` implementation, because it
   is marginally faster.  How much faster depends on the exact version
   of x/crypto/curve25519 being used, with newer versions suffering a
   fairly massive performance regression due to the move away from
   assembly lifted out of SUPERCOP.
 * circl is alone in the use of BMI2 for `X25519/ScalarMult`.
 * As the system used for benchmarking has AVX2, a subtantial fraction
   of the curve25519-voi routines benchmarked are written in assembly
   language.

##### purego (Assembly optimizations disabled)

```
name \ time/op            stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      160µs ± 0%      67µs ± 0%                      48µs ± 0%
X25519/ScalarMult          160µs ± 0%     108µs ± 0%                     118µs ± 0%
Ed25519/NewKeyFromSeed    58.4µs ± 0%    61.0µs ± 0%                    49.0µs ± 1%
Ed25519/Sign              73.0µs ± 0%    63.8µs ± 0%                    52.2µs ± 0%
Ed25519/Verify             181µs ± 0%     133µs ± 0%                     131µs ± 0%
Ed25519/Verify_ZIP215                                       192µs ± 0%   109µs ± 0%
Ed25519/VerifyBatch_1                                       231µs ± 0%   164µs ± 0%
Ed25519/VerifyBatch_8                                       826µs ± 0%   602µs ± 0%
Ed25519/VerifyBatch_16                                     1.51ms ± 0%  1.10ms ± 0%
Ed25519/VerifyBatch_32                                     2.87ms ± 0%  2.10ms ± 0%
Ed25519/VerifyBatch_64                                     5.57ms ± 0%  4.10ms ± 0%
Ed25519/VerifyBatch_128                                    11.0ms ± 0%   8.2ms ± 0%
Ed25519/VerifyBatch_256                                    22.0ms ± 0%  15.2ms ± 0%
Ed25519/VerifyBatch_512                                    44.1ms ± 0%  28.3ms ± 0%
Ed25519/VerifyBatch_1024                                   88.5ms ± 0%  52.8ms ± 0%

name \ alloc/op           stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00B          0.00B                          0.00B
X25519/ScalarMult          0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed     0.00B          0.00B                          0.00B
Ed25519/Sign               0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify             0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                       0.00B        0.00B
Ed25519/VerifyBatch_1                                      5.65kB ± 0%  5.43kB ± 0%
Ed25519/VerifyBatch_8                                      31.9kB ± 0%  34.0kB ± 0%
Ed25519/VerifyBatch_16                                     69.3kB ± 0%  65.8kB ± 0%
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
Ed25519/NewExpandedPublicKey               11.4µs ± 1%
Ed25519/Verify              82.4µs ± 1%    73.2µs ± 0%  -11.16%  (p=0.008 n=5+5)
Ed25519/Verify_ZIP215       74.0µs ± 1%    64.4µs ± 1%  -12.97%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1        105µs ± 0%      93µs ± 0%  -11.25%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8        404µs ± 0%     313µs ± 1%  -22.48%  (p=0.016 n=4+5)
Ed25519/VerifyBatch_16       746µs ± 0%     565µs ± 1%  -24.27%  (p=0.016 n=4+5)
Ed25519/VerifyBatch_32      1.42ms ± 0%    1.06ms ± 0%  -25.61%  (p=0.016 n=4+5)
Ed25519/VerifyBatch_64      2.79ms ± 0%    2.06ms ± 3%  -25.98%  (p=0.016 n=4+5)
Ed25519/VerifyBatch_128     5.39ms ± 1%    3.92ms ± 0%  -27.26%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256     10.1ms ± 4%     7.1ms ± 0%  -29.69%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512     19.1ms ± 0%    13.3ms ± 0%  -30.58%  (p=0.016 n=4+5)
Ed25519/VerifyBatch_1024    36.1ms ± 0%    24.4ms ± 0%  -32.58%  (p=0.008 n=5+5)

name                      old alloc/op   new alloc/op   delta
Ed25519/NewExpandedPublicKey               1.50kB ± 0%
Ed25519/Verify               0.00B          0.00B          ~     (all equal)
Ed25519/Verify_ZIP215        0.00B          0.00B          ~     (all equal)
Ed25519/VerifyBatch_1       5.43kB ± 0%    3.93kB ± 0%  -27.69%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8       34.0kB ± 0%    21.9kB ± 0%  -35.44%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16      65.8kB ± 0%    41.8kB ± 0%  -36.55%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32       138kB ± 0%      89kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_64       267kB ± 0%     171kB ± 0%  -36.08%  (p=0.000 n=5+4)
Ed25519/VerifyBatch_128      353kB ± 0%     161kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_256      701kB ± 0%     316kB ± 0%  -54.96%  (p=0.000 n=4+5)
Ed25519/VerifyBatch_512     1.40MB ± 0%    0.63MB ± 0%  -55.01%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024    2.76MB ± 0%    1.22MB ± 0%  -55.86%  (p=0.029 n=4+4)

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
