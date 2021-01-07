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

#### Notes

The curve25519-dalek crate makes use of "modern" programing language
features not available in Go.  This package's mid-level API attempts
to provide something usable by developers familiar with idiomatic Go,
and thus has more sharp edges, but in all honestly, developers that
opt to use the mid-level API in theory already know what they are
getting into.  Stability of the mid-level API is currently NOT
guaranteed.

The curve25519-dalek crate has a series of nice vectorized backends
written using SIMD intrinsics.  Go has no SIMD intrinsics, and the
assembly dialect is anything but nice, and thus they are currently
omitted.

Memory sanitization while maintaining reasonable performance in Go is
a hard/unsolved problem, and this package makes no attempts to do so.
Anyone that mentions memguard will be asked to re-read the previous
sentence again, and then be mercilessly mocked.  It is worth noting
that the standard library does not do this appropriately either.

Go prior to 1.13 provides no guarantees regarding the timing
characteristics of the relevant `math/bits` intrinsics that are used
by this package.  Additionally, `bits.Mul64` and `bits.Add64` must be
optimized correctly by the compiler for this implementation to be fast.
If this is not the case on your architecture, the author recommends
complaining to the Go developers.

A dedicated 32 bit code path is omitted to save development and
maintenance effort as such architectures are increasingly irrelevant.
That said, the package is written in such a way that it would be
relatively easy to add such a thing, if the demand is high enough.

#### TODO

 * Implement Ed25519 batch verification.

 * Add the functions that were omitted in the initial porting effort.
   This would primarily be for completeness, none of the use cases the
   author is interested in require them at the moment, likely due
   to lack of imagination.

 * Try to get performance of certain operations closer to this author's
   previous attempt at a better Go Ed25519, which was ed25519-donna
   based.
