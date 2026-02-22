package matter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// TODO: clarify the different assets to be provided, and when and who should provide them (e.g. a controller has more assets than a device) etc.

// CertificateManager manages certificates and keys for a Fabric.
type CertificateManager interface {
	GetRootPublicKey() []byte
	GetCertificate(nodeID uint64) (*x509.Certificate, error)
	GetPrivkey(nodeID uint64) (*ecdsa.PrivateKey, error)
}

// Fabric represents a Matter Fabric.
type Fabric struct {
	id                 uint64
	nodeID             uint64
	ipk                []byte
	CertificateManager CertificateManager
}

// NewFabric creates a new Fabric instance.
func NewFabric(id uint64, nodeID uint64, ipk []byte, certManager CertificateManager) *Fabric {
	return &Fabric{
		id:                 id,
		nodeID:             nodeID,
		ipk:                ipk,
		CertificateManager: certManager,
	}
}

// SerializeCertificateIntoMatter converts an X.509 certificate to the Matter TLV format.
func (f *Fabric) SerializeCertificateIntoMatter(cert *x509.Certificate) []byte {
	// Placeholder for certificate serialization logic.
	// In a real implementation, this would convert the X.509 cert to Matter's TLV format.
	// For now, we return the raw DER bytes as a placeholder, or a dummy value.
	if cert == nil {
		return []byte("dummy_cert")
	}
	return cert.Raw
}

// MemCertificateManager is an in-memory certificate manager that generates keys and certificates.
type MemCertificateManager struct {
	RootKey   *ecdsa.PrivateKey
	RootCert  *x509.Certificate
	NodeKeys  map[uint64]*ecdsa.PrivateKey
	NodeCerts map[uint64]*x509.Certificate
}

// NewGeneratedCertificateManager creates a new MemCertificateManager with a generated Root CA.
func NewGeneratedCertificateManager() (*MemCertificateManager, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Matter Test Root"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &MemCertificateManager{
		RootKey:   rootKey,
		RootCert:  rootCert,
		NodeKeys:  make(map[uint64]*ecdsa.PrivateKey),
		NodeCerts: make(map[uint64]*x509.Certificate),
	}, nil
}

func (m *MemCertificateManager) GetRootPublicKey() []byte {
	return elliptic.Marshal(m.RootKey.Curve, m.RootKey.X, m.RootKey.Y)
}

func (m *MemCertificateManager) GetCertificate(nodeID uint64) (*x509.Certificate, error) {
	if cert, ok := m.NodeCerts[nodeID]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(nodeID)),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("Node-%d", nodeID),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, m.RootCert, &key.PublicKey, m.RootKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	m.NodeKeys[nodeID] = key
	m.NodeCerts[nodeID] = cert

	return cert, nil
}

func (m *MemCertificateManager) GetPrivkey(nodeID uint64) (*ecdsa.PrivateKey, error) {
	if key, ok := m.NodeKeys[nodeID]; ok {
		return key, nil
	}
	if _, err := m.GetCertificate(nodeID); err != nil {
		return nil, err
	}
	return m.NodeKeys[nodeID], nil
}
