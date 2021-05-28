// Copyright (c) 2019 George Tankersley
// Copyright (c) 2019 Henry de Valence
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

package merlin

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/mimoo/StrobeGo/strobe"
)

const (
	merlinProtocolLabel  = "Merlin v1.0"
	domainSeparatorLabel = "dom-sep"
)

type Transcript struct {
	s strobe.Strobe
}

func NewTranscript(appLabel string) *Transcript {
	t := Transcript{
		s: strobe.InitStrobe(merlinProtocolLabel, 128),
	}

	t.AppendMessage([]byte(domainSeparatorLabel), []byte(appLabel))
	return &t
}

// Clone returns a deep-copy of the transcript.
func (t *Transcript) Clone() *Transcript {
	return &Transcript{
		s: *t.s.Clone(),
	}
}

// Append adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessage(label, message []byte) {
	// AD[label || le32(len(message))](message)

	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(message)))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	t.s.AD(false, message)
}

// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. See the Transcript Protocols section of the Merlin website
// for details on labels.
func (t *Transcript) ExtractBytes(label []byte, outLen int) []byte {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outLen))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	// A PRF call directly to the output buffer (in the style of an append API)
	// would be better, but our underlying STROBE library forces an allocation
	// here.
	outBytes := t.s.PRF(outLen)
	return outBytes
}

// BuildRng constructs a transcript RNG builder bound to the current
// transcript state.
func (t *Transcript) BuildRng() *TranscriptRngBuilder {
	return &TranscriptRngBuilder{
		s: t.s.Clone(),
	}
}

// TranscriptRngBuilder constructs a transcript RNG by rekeying the transcript
// with prover secrets and an external RNG.
type TranscriptRngBuilder struct {
	s *strobe.Strobe
}

// RekeyWithWitnessBytes rekeys the transcript using the provided witness data.
func (rb *TranscriptRngBuilder) RekeyWithWitnessBytes(label, witness []byte) *TranscriptRngBuilder {
	// AD[label || le32(len(witness))](witness)

	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(witness)))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	rb.s.AD(true, labelSize)

	rb.s.KEY(witness)

	return rb
}

// Finalize rekeys and finalizes the transcript, and constructs the RNG.
// If rng is nil, crypto/rand.Reader will be used.
//
// Note: This invalidates the TranscriptRngBuilder.
func (rb *TranscriptRngBuilder) Finalize(rng io.Reader) (io.Reader, error) {
	if rng == nil {
		rng = rand.Reader
	}

	randomBytes := make([]byte, 32)
	if _, err := io.ReadFull(rng, randomBytes); err != nil {
		return nil, fmt.Errorf("internal/merlin: failed to read entropy: %w", err)
	}

	rb.s.AD(true, []byte("rng"))
	rb.s.KEY(randomBytes)

	r := &transcriptRng{
		s: rb.s,
	}
	rb.s = nil // Crash on further calls to rb.

	return r, nil
}

type transcriptRng struct {
	s *strobe.Strobe
}

func (rng *transcriptRng) Read(p []byte) (int, error) {
	l := len(p)

	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(l))
	rng.s.AD(true, sizeBuffer)

	// The StrobeGo API does not allow specifying a destination buffer
	// for the PRF call, so this incurs the hit of an allocate + copy.
	b := rng.s.PRF(l)
	copy(p, b)

	return l, nil
}
