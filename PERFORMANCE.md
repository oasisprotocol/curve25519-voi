### curve25519-voi performance

All measurements were taken on an Intel(R) Core(TM) i7-10510U @ 1.80GHz
with turbo disabled, using Go 1.16.3 as the toolchain.  As there are
multiple definitions of "Ed25519 signature verification", curve25519-voi
was configured for each benchmark to use as similar verification semantics
as possible where relevant.

| Implementation      | Version/Commit                           |
| ------------------- | ---------------------------------------- |
| crypto/ed25519      | 1.16.3                                   |
| x/crypto/curve25519 | v0.0.0-20210322153248-0c34fe9e7dc2       |
| circl               | v1.0.1-0.20210315192536-3977848c88c6     |
| ed25519consensus    | v0.0.0-20210430192048-0962ce16b305       |
| curve25519-voi      | 05051a372c94f9d2ee6a9adae0c7899009dec3f6 |

##### Native

```
name \ time/op            stdlib       circl          ed25519consensus  voi
X25519/ScalarBaseMult     81.0µs ± 0%    44.2µs ± 1%                    25.0µs ± 1%
X25519/ScalarMult         80.1µs ± 0%    65.2µs ± 0%                    80.5µs ± 0%
Ed25519/NewKeyFromSeed     105µs ± 1%      55µs ± 1%                      26µs ± 0%
Ed25519/Sign               109µs ± 0%      58µs ± 1%                      29µs ± 0%
Ed25519/Verify             297µs ± 2%     124µs ± 0%                      84µs ± 1%
Ed25519/Verify_ZIP215                                       137µs ± 1%    77µs ± 1%
Ed25519/VerifyBatch_1                                       173µs ± 1%   105µs ± 1%
Ed25519/VerifyBatch_8                                       608µs ± 2%   415µs ± 3%
Ed25519/VerifyBatch_16                                     1.10ms ± 1%  0.75ms ± 0%
Ed25519/VerifyBatch_32                                     2.09ms ± 1%  1.44ms ± 1%
Ed25519/VerifyBatch_64                                     4.05ms ± 0%  2.82ms ± 0%
Ed25519/VerifyBatch_128                                    8.03ms ± 1%  5.52ms ± 1%
Ed25519/VerifyBatch_256                                    16.0ms ± 0%  10.3ms ± 0%
Ed25519/VerifyBatch_512                                    32.1ms ± 0%  19.6ms ± 1%
Ed25519/VerifyBatch_1024                                   64.5ms ± 1%  37.1ms ± 0%

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
   use the x/crypto/curve25519 `ScalarMult` implementation, because there
   is no reason not to, and it is hand-optimized assembly language.
 * circl is alone in the use of BMI2 for `X25519/ScalarMult`.
 * As the system used for benchmarking has AVX2, a subtantial fraction
   of the curve25519-voi routines benchmarked are written in assembly
   language.

##### purego (Assembly optimizations disabled)

```
name \ time/op            stdlib      circl          ed25519consensus  voi
X25519/ScalarBaseMult     322µs ± 1%      73µs ± 0%                      56µs ± 1%
X25519/ScalarMult         325µs ± 1%     118µs ± 0%                     131µs ± 2%
Ed25519/NewKeyFromSeed    105µs ± 0%      67µs ± 1%                      57µs ± 1%
Ed25519/Sign              109µs ± 1%      69µs ± 1%                      60µs ± 0%
Ed25519/Verify            296µs ± 1%     146µs ± 0%                     139µs ± 1%
Ed25519/Verify_ZIP215                                      200µs ± 0%   115µs ± 1%
Ed25519/VerifyBatch_1                                      245µs ± 0%   174µs ± 0%
Ed25519/VerifyBatch_8                                      872µs ± 0%   635µs ± 1%
Ed25519/VerifyBatch_16                                    1.57ms ± 0%  1.14ms ± 0%
Ed25519/VerifyBatch_32                                    2.99ms ± 0%  2.18ms ± 1%
Ed25519/VerifyBatch_64                                    5.81ms ± 0%  4.25ms ± 0%
Ed25519/VerifyBatch_128                                   11.5ms ± 0%   8.6ms ± 0%
Ed25519/VerifyBatch_256                                   22.9ms ± 0%  15.9ms ± 1%
Ed25519/VerifyBatch_512                                   46.0ms ± 0%  29.7ms ± 1%
Ed25519/VerifyBatch_1024                                  92.4ms ± 2%  54.9ms ± 1%

name \ alloc/op           stdlib      circl          ed25519consensus  voi
X25519/ScalarBaseMult     0.00B          0.00B                          0.00B
X25519/ScalarMult         0.00B          0.00B                          0.00B
Ed25519/NewKeyFromSeed    0.00B          0.00B                          0.00B
Ed25519/Sign              0.00B        416.00B ± 0%                    64.00B ± 0%
Ed25519/Verify            0.00B       4784.00B ± 0%                     0.00B
Ed25519/Verify_ZIP215                                      0.00B        0.00B
Ed25519/VerifyBatch_1                                     5.65kB ± 0%  5.43kB ± 0%
Ed25519/VerifyBatch_8                                     31.9kB ± 0%  34.0kB ± 0%
Ed25519/VerifyBatch_16                                    69.3kB ± 0%  65.8kB ± 0%
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
Ed25519/NewExpandedPublicKey               11.6µs ± 1%
Ed25519/Verify              83.6µs ± 1%    73.5µs ± 0%  -12.01%  (p=0.008 n=5+5)
Ed25519/Verify_ZIP215       76.7µs ± 1%    64.3µs ± 0%  -16.17%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1        105µs ± 1%      96µs ± 1%   -9.14%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8        415µs ± 3%     316µs ± 1%  -23.83%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16       755µs ± 0%     568µs ± 0%  -24.79%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32      1.44ms ± 1%    1.07ms ± 0%  -25.77%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_64      2.82ms ± 0%    2.07ms ± 0%  -26.48%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_128     5.52ms ± 1%    3.99ms ± 1%  -27.66%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_256     10.3ms ± 0%     7.3ms ± 0%  -29.60%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_512     19.6ms ± 1%    13.5ms ± 0%  -31.26%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_1024    37.1ms ± 0%    24.8ms ± 0%  -33.01%  (p=0.008 n=5+5)

name                      old alloc/op   new alloc/op   delta
Ed25519/NewExpandedPublicKey               1.50kB ± 0%
Ed25519/Verify               0.00B          0.00B          ~     (all equal)
Ed25519/Verify_ZIP215        0.00B          0.00B          ~     (all equal)
Ed25519/VerifyBatch_1       5.43kB ± 0%    3.93kB ± 0%  -27.69%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_8       34.0kB ± 0%    21.9kB ± 0%  -35.44%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_16      65.8kB ± 0%    41.8kB ± 0%  -36.55%  (p=0.008 n=5+5)
Ed25519/VerifyBatch_32       138kB ± 0%      89kB ± 0%  -34.98%  (p=0.029 n=4+4)
Ed25519/VerifyBatch_64       267kB ± 0%     171kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_128      353kB ± 0%     161kB ± 0%     ~     (p=0.079 n=4+5)
Ed25519/VerifyBatch_256      701kB ± 0%     316kB ± 0%  -54.96%  (p=0.008 n=5+5)
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
