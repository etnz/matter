package securechannel

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCertificateEncodingDecoding(t *testing.T) {
	// 1. Generate a certificate using the existing manager helper
	cm, err := NewGeneratedCertificateManager()
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	// Generate a node certificate
	nodeID := uint64(12345678910)
	cert, err := cm.Certificate(nodeID)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Get the private key to verify signature later
	privKey, err := cm.PrivateKey(nodeID)
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}

	// 2. Serialize the certificate to Matter TLV
	tlvBytes, err := CertificateToMatterTLV(cert)
	if err != nil {
		t.Fatalf("Failed to serialize certificate: %v", err)
	}

	// 3. Print the bits (Hex format)
	t.Logf("Serialized Certificate (Hex): %s", hex.EncodeToString(tlvBytes))

	// 4. Read the certificate back
	decodedCert, err := ParseCertificateFromMatter(tlvBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from TLV: %v", err)
	}

	// 5. Verify keys by signing and verifying a piece of text
	text := []byte("This is a test message for signature verification")
	hash := sha256.Sum256(text)

	// Sign with the original private key
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify with the decoded public key
	decodedPubKey, ok := decodedCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Decoded public key is not of type *ecdsa.PublicKey")
	}

	if !ecdsa.Verify(decodedPubKey, hash[:], r, s) {
		t.Errorf("Signature verification failed using the decoded public key")
	} else {
		t.Log("Signature verification successful")
	}
}
