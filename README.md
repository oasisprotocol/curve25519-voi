### curve25519-voi

> It was only machinery.  I’m surprised it’s lasted as long as it has,
> frankly.  There must still be some residual damage-repair capability.
> We Demarchists build for posterity, you know.

This package aims to provide a modern X25519/Ed25519/sr25519
implementation for Go, mostly derived from curve25519-dalek.  The
primary motivation is to hopefully provide a worthy alternative to
the current state of available Go implementations, which is best
described as "a gigantic mess of ref10 and donna ports".  The irony
of the previous statement in the light of curve25519-dalek's lineage
does not escape this author.

#### WARNING

***DO NOT BOTHER THE curve25519-dalek DEVELOPERS ABOUT THIS PACKAGE***

#### Package structure

 * curve: A mid-level API in the spirit of curve25519-dalek.
 * primitives/x25519: A X25519 implementation like `x/crypto/curve25519`.
 * primitives/ed25519: A Ed25519 implementation like `crypto/ed25519`.
 * primitives/sr25519: A sr25519 implementation like `https://github.com/w3f/schnorrkel`.

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
