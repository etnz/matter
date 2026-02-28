package tlv_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/etnz/matter/tlv"
)

func TestEncodingDeterminism(t *testing.T) {
	// Create a complex tlv.Struct with nested fields to ensure deep determinism.
	// Maps in Go have random iteration order, so if we don't sort keys during encoding,
	// the output bytes will differ between runs.
	val := tlv.Struct{
		tlv.ContextTag(0): uint8(0),
		tlv.ContextTag(2): uint8(2),
		tlv.ContextTag(1): uint8(1),
		tlv.ContextTag(3): tlv.Struct{
			tlv.ContextTag(2): uint16(20),
			tlv.ContextTag(1): uint16(10),
		},
	}

	var firstDigest []byte

	for i := 0; i < 100; i++ {
		encoded := val.Bytes()
		sum := sha256.Sum256(encoded)
		digest := sum[:]

		if firstDigest == nil {
			firstDigest = digest
		} else if !bytes.Equal(firstDigest, digest) {
			t.Fatalf("TLV encoding is not deterministic. Iteration %d produced a different digest.", i)
		}
	}
}
