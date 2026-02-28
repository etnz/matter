package securechannel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/etnz/matter/tlv"
)

var (
	oidNodeID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	oidFabricID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}
)

// Matter Epoch: 2000-01-01 00:00:00 UTC
var matterEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func timeToMatterEpoch(t time.Time) uint32 {
	diff := t.Sub(matterEpoch)
	if diff < 0 {
		return 0
	}
	return uint32(diff.Seconds())
}

type ecdsaSignature struct {
	R, S *big.Int
}

// CertificateToMatterTLV converts an X.509 certificate to the Matter TLV format.
func CertificateToMatterTLV(cert *x509.Certificate) ([]byte, error) {
	s := tlv.Struct{
		tlv.ContextTag(1): cert.SerialNumber.Bytes(),
		tlv.ContextTag(2): uint8(1), // Signature Algorithm: ECDSA-with-SHA256
		tlv.ContextTag(3): encodeDN(cert.Issuer),
		tlv.ContextTag(4): timeToMatterEpoch(cert.NotBefore),
		tlv.ContextTag(5): timeToMatterEpoch(cert.NotAfter),
		tlv.ContextTag(6): encodeDN(cert.Subject),
		tlv.ContextTag(7): uint8(1), // Public Key Algorithm: EC
		tlv.ContextTag(8): uint8(1), // Elliptic Curve ID: prime256v1
	}

	// Public Key
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}
	s[tlv.ContextTag(9)] = elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)

	// Extensions
	exts, err := encodeExtensions(cert)
	if err != nil {
		return nil, err
	}
	s[tlv.ContextTag(10)] = exts

	// Signature
	// Convert ASN.1 signature to raw r|s
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(cert.Signature, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature: %v", err)
	}
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	rawSig := make([]byte, 64)
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)
	s[tlv.ContextTag(11)] = rawSig

	return tlv.Encode(s), nil
}

// ParseCertificateFromMatter converts a Matter TLV certificate to an X.509 certificate.
func ParseCertificateFromMatter(data []byte) (*x509.Certificate, error) {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return nil, fmt.Errorf("expected struct, got %T", val)
	}

	cert := &x509.Certificate{}

	// Public Key (Tag 9)
	if v, ok := st[tlv.ContextTag(9)]; ok {
		pubKeyBytes := v.([]byte)
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
		if x == nil {
			return nil, fmt.Errorf("invalid public key")
		}
		cert.PublicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		cert.PublicKeyAlgorithm = x509.ECDSA
	}

	// Signature (Tag 11)
	if v, ok := st[tlv.ContextTag(11)]; ok {
		rawSig := v.([]byte)
		if len(rawSig) != 64 {
			return nil, fmt.Errorf("invalid signature length")
		}
		r := new(big.Int).SetBytes(rawSig[:32])
		s := new(big.Int).SetBytes(rawSig[32:])
		sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
		if err != nil {
			return nil, err
		}
		cert.Signature = sig
		cert.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	return cert, nil
}

func encodeDN(name pkix.Name) tlv.List {
	var l tlv.List
	for _, name := range name.Names {
		var tag tlv.Tag
		var val any

		if name.Type.Equal(oidNodeID) {
			tag = tlv.ContextTag(1)
			if v, ok := name.Value.(int64); ok {
				val = uint64(v)
			} else if v, ok := name.Value.(uint64); ok {
				val = v
			}
		} else if name.Type.Equal(oidFabricID) {
			tag = tlv.ContextTag(5)
			if v, ok := name.Value.(int64); ok {
				val = uint64(v)
			} else if v, ok := name.Value.(uint64); ok {
				val = v
			}
		}

		if tag.Control != 0 {
			l = append(l, tlv.Element{Tag: tag, Value: val})
		}
	}
	return l
}

func encodeExtensions(cert *x509.Certificate) (tlv.List, error) {
	var l tlv.List

	// Basic Constraints (Tag 1)
	if cert.BasicConstraintsValid {
		bc := tlv.Struct{
			tlv.ContextTag(1): cert.IsCA,
		}
		if cert.MaxPathLen > 0 || (cert.MaxPathLenZero && cert.IsCA) {
			bc[tlv.ContextTag(2)] = uint8(cert.MaxPathLen)
		}
		l = append(l, tlv.Element{Tag: tlv.ContextTag(1), Value: bc})
	}

	// Key Usage (Tag 2)
	if cert.KeyUsage != 0 {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(2), Value: uint16(cert.KeyUsage)})
	}

	// Extended Key Usage (Tag 3)
	if len(cert.ExtKeyUsage) > 0 {
		var ekuList tlv.List
		for _, u := range cert.ExtKeyUsage {
			var val uint8
			switch u {
			case x509.ExtKeyUsageServerAuth:
				val = 1
			case x509.ExtKeyUsageClientAuth:
				val = 2
			case x509.ExtKeyUsageCodeSigning:
				val = 3
			case x509.ExtKeyUsageEmailProtection:
				val = 4
			case x509.ExtKeyUsageTimeStamping:
				val = 5
			case x509.ExtKeyUsageOCSPSigning:
				val = 6
			}
			if val != 0 {
				ekuList = append(ekuList, tlv.Element{Tag: tlv.AnonymousTag, Value: val})
			}
		}
		l = append(l, tlv.Element{Tag: tlv.ContextTag(3), Value: ekuList})
	}

	// Subject Key ID (Tag 4)
	if len(cert.SubjectKeyId) > 0 {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(4), Value: cert.SubjectKeyId})
	}

	// Authority Key ID (Tag 5)
	if len(cert.AuthorityKeyId) > 0 {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(5), Value: cert.AuthorityKeyId})
	}

	return l, nil
}
