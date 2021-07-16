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
| curve25519-voi      | d78c2d9c35da693034ddbbb2242a8f43b6be2348 |

##### Native

```
name \ time/op            stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      107µs ± 0%      44µs ± 0%                      25µs ± 0%
X25519/ScalarMult          107µs ± 0%      65µs ± 0%                     107µs ± 1%
Ed25519/NewKeyFromSeed    42.8µs ± 0%    54.4µs ± 1%                    25.4µs ± 1%
Ed25519/Sign              52.9µs ± 1%    56.6µs ± 0%                    28.6µs ± 0%
Ed25519/Verify             125µs ± 0%     121µs ± 1%                      83µs ± 1%
Ed25519/Verify_ZIP215                                       129µs ± 0%    74µs ± 0%
Ed25519/VerifyBatch_1                                       160µs ± 0%   104µs ± 0%
Ed25519/VerifyBatch_8                                       572µs ± 0%   402µs ± 0%
Ed25519/VerifyBatch_16                                     1.05ms ± 0%  0.74ms ± 0%
Ed25519/VerifyBatch_32                                     1.99ms ± 0%  1.42ms ± 0%
Ed25519/VerifyBatch_64                                     3.88ms ± 0%  2.78ms ± 1%
Ed25519/VerifyBatch_128                                    7.66ms ± 0%  5.32ms ± 0%
Ed25519/VerifyBatch_256                                    15.3ms ± 0%   9.5ms ± 0%
Ed25519/VerifyBatch_512                                    30.8ms ± 0%  17.6ms ± 0%
Ed25519/VerifyBatch_1024                                   61.7ms ± 0%  32.5ms ± 0%

name \ alloc/op           stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00B          0.00B                          0.00B
X25519/ScalarMult          0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed     0.00B          0.00B                          0.00B
Ed25519/Sign               0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify             0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                       0.00B        0.00B
Ed25519/VerifyBatch_1                                      5.65kB ± 0%  5.59kB ± 0%
Ed25519/VerifyBatch_8                                      31.9kB ± 0%  36.2kB ± 0%
Ed25519/VerifyBatch_16                                     69.3kB ± 0%  70.0kB ± 0%
Ed25519/VerifyBatch_32                                      130kB ± 0%   146kB ± 0%
Ed25519/VerifyBatch_64                                      254kB ± 0%   283kB ± 0%
Ed25519/VerifyBatch_128                                     497kB ± 0%   334kB ± 0%
Ed25519/VerifyBatch_256                                     970kB ± 0%   521kB ± 0%
Ed25519/VerifyBatch_512                                    1.93MB ± 0%  0.90MB ± 0%
Ed25519/VerifyBatch_1024                                   3.82MB ± 0%  1.61MB ± 0%

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
Ed25519/VerifyBatch_128                                       270 ± 0%     203 ± 0%
Ed25519/VerifyBatch_256                                       527 ± 0%     204 ± 0%
Ed25519/VerifyBatch_512                                     1.04k ± 0%   0.20k ± 0%
Ed25519/VerifyBatch_1024                                    2.06k ± 0%   0.21k ± 0%
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
X25519/ScalarBaseMult      160µs ± 1%      67µs ± 0%                      48µs ± 0%
X25519/ScalarMult          161µs ± 1%     108µs ± 0%                     119µs ± 1%
Ed25519/NewKeyFromSeed    58.4µs ± 0%    61.0µs ± 0%                    48.8µs ± 0%
Ed25519/Sign              72.9µs ± 0%    63.7µs ± 0%                    52.1µs ± 0%
Ed25519/Verify             181µs ± 0%     133µs ± 1%                     131µs ± 0%
Ed25519/Verify_ZIP215                                       191µs ± 1%   109µs ± 0%
Ed25519/VerifyBatch_1                                       231µs ± 0%   164µs ± 0%
Ed25519/VerifyBatch_8                                       831µs ± 2%   602µs ± 0%
Ed25519/VerifyBatch_16                                     1.51ms ± 0%  1.10ms ± 0%
Ed25519/VerifyBatch_32                                     2.86ms ± 0%  2.10ms ± 0%
Ed25519/VerifyBatch_64                                     5.57ms ± 0%  4.10ms ± 0%
Ed25519/VerifyBatch_128                                    11.0ms ± 1%   8.0ms ± 0%
Ed25519/VerifyBatch_256                                    22.0ms ± 0%  14.2ms ± 0%
Ed25519/VerifyBatch_512                                    44.0ms ± 0%  25.9ms ± 1%
Ed25519/VerifyBatch_1024                                   88.2ms ± 1%  47.2ms ± 0%

name \ alloc/op           stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult      0.00B          0.00B                          0.00B
X25519/ScalarMult          0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed     0.00B          0.00B                          0.00B
Ed25519/Sign               0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify             0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                       0.00B        0.00B
Ed25519/VerifyBatch_1                                      5.65kB ± 0%  5.59kB ± 0%
Ed25519/VerifyBatch_8                                      31.9kB ± 0%  36.2kB ± 0%
Ed25519/VerifyBatch_16                                     69.3kB ± 0%  70.0kB ± 0%
Ed25519/VerifyBatch_32                                      130kB ± 0%   146kB ± 0%
Ed25519/VerifyBatch_64                                      254kB ± 0%   283kB ± 0%
Ed25519/VerifyBatch_128                                     497kB ± 0%   334kB ± 0%
Ed25519/VerifyBatch_256                                     970kB ± 0%   521kB ± 0%
Ed25519/VerifyBatch_512                                    1.93MB ± 0%  0.90MB ± 0%
Ed25519/VerifyBatch_1024                                   3.82MB ± 0%  1.61MB ± 0%

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
Ed25519/VerifyBatch_128                                       270 ± 0%     203 ± 0%
Ed25519/VerifyBatch_256                                       527 ± 0%     204 ± 0%
Ed25519/VerifyBatch_512                                     1.04k ± 0%   0.20k ± 0%
Ed25519/VerifyBatch_1024                                    2.06k ± 0%   0.21k ± 0%
```

##### Precomputed verification

curve25519-voi supports expanding public keys, to accelerate repeated
Ed25519 signature verification with the same public key.  This will be a
net performance gain if a public key will be used to verify signatures
more than once, and costs approximately 1.47 KiB of memory per public key.

The batch verification code is written to attempt to leverage pre-computation
where possible, and will convert non-expanded public keys to expanded form
internally by default unless the batch grows over the size supported by
the precomputed multiscalar multiply.

```
name                      old time/op    new time/op    delta
Ed25519/NewExpandedPublicKey               11.3µs ± 0%
Ed25519/Verify              82.6µs ± 1%    73.3µs ± 0%  -11.27%  (p=0.008 n=5+5)
Ed25519/Verify_ZIP215       74.0µs ± 0%    65.0µs ± 1%  -12.18%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1        104µs ± 0%      92µs ± 0%  -11.40%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8        402µs ± 0%     310µs ± 0%  -22.84%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16       742µs ± 0%     560µs ± 0%  -24.53%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32      1.42ms ± 0%    1.05ms ± 1%  -25.80%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64      2.78ms ± 1%    2.03ms ± 0%  -26.99%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128     5.32ms ± 0%    3.96ms ± 0%  -25.54%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256     9.50ms ± 0%    7.22ms ± 1%  -23.98%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512     17.6ms ± 0%    13.4ms ± 0%  -23.66%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024    32.5ms ± 0%    24.6ms ± 0%  -24.28%  (p=0.008 n=5+5)

name                      old alloc/op   new alloc/op   delta
Ed25519/NewExpandedPublicKey               1.50kB ± 0%
Ed25519/Verify               0.00B          0.00B          ~     (all equal)
Ed25519/Verify_ZIP215        0.00B          0.00B          ~     (all equal)
Ed25519/VerifyBatch_1       5.59kB ± 0%    4.09kB ± 0%  -26.90%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8       36.2kB ± 0%    24.2kB ± 0%  -33.22%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16      70.0kB ± 0%    46.0kB ± 0%  -34.36%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32       146kB ± 0%      97kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_64       283kB ± 0%     187kB ± 0%  -34.01%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128      334kB ± 0%     192kB ± 0%  -42.35%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256      521kB ± 0%     379kB ± 0%  -27.15%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512      899kB ± 0%     757kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_1024    1.61MB ± 0%    1.47MB ± 0%   -8.76%  (p=0.000 n=4+5)

name                      old allocs/op  new allocs/op  delta
Ed25519/NewExpandedPublicKey                 2.00 ± 0%
Ed25519/Verify                0.00           0.00          ~     (all equal)
Ed25519/Verify_ZIP215         0.00           0.00          ~     (all equal)
Ed25519/VerifyBatch_1         12.0 ± 0%      10.0 ± 0%  -16.67%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8         29.0 ± 0%      13.0 ± 0%  -55.17%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16        46.0 ± 0%      14.0 ± 0%  -69.57%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32        79.0 ± 0%      15.0 ± 0%  -81.01%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64         144 ± 0%        16 ± 0%  -88.89%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128        203 ± 0%        15 ± 0%  -92.61%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256        204 ± 0%        16 ± 0%  -92.16%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512        205 ± 0%        17 ± 0%  -91.71%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024       206 ± 0%        18 ± 0%  -91.26%  (p=0.008 n=5+5)
```
