package securechannel

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

// CertificateManager manages certificates and keys for a Fabric.
type CertificateManager interface {
	PublicKey() []byte
	Certificate(nodeID uint64) (*x509.Certificate, error)
	PrivateKey(nodeID uint64) (*ecdsa.PrivateKey, error)
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

func (f *Fabric) IPK() []byte           { return f.ipk }
func (f *Fabric) ID() uint64            { return f.id }
func (f *Fabric) NodeID() uint64        { return f.nodeID }
func (f *Fabric) RootPublicKey() []byte { return f.CertificateManager.PublicKey() }
func (f *Fabric) Certificate(nodeID uint64) (*x509.Certificate, error) {
	return f.CertificateManager.Certificate(nodeID)
}
func (f *Fabric) PrivateKey(nodeID uint64) (*ecdsa.PrivateKey, error) {
	return f.CertificateManager.PrivateKey(nodeID)
}

// SerializeCertificateIntoMatter converts an X.509 certificate to the Matter TLV format.
func (f *Fabric) SerializeCertificateIntoMatter(cert *x509.Certificate) []byte {
	data, err := CertificateToMatterTLV(cert)
	if err != nil {
		return nil
	}
	return data
}

// MemCertificateManager is an in-memory certificate manager that generates keys and certificates.
// This is a simple implementation for testing purposes and should not be used in production as it does not persist any data.
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

func (m *MemCertificateManager) PublicKey() []byte {
	return elliptic.Marshal(m.RootKey.Curve, m.RootKey.X, m.RootKey.Y)
}

func (m *MemCertificateManager) Certificate(nodeID uint64) (*x509.Certificate, error) {
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

func (m *MemCertificateManager) PrivateKey(nodeID uint64) (*ecdsa.PrivateKey, error) {
	if key, ok := m.NodeKeys[nodeID]; ok {
		return key, nil
	}
	if _, err := m.Certificate(nodeID); err != nil {
		return nil, err
	}
	return m.NodeKeys[nodeID], nil
}
