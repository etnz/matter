package securechannel

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/tom-code/gomat/ccm"
	"golang.org/x/crypto/hkdf"
)

// caseContext manages the state of a Certificate Authenticated Session Establishment handshake.
type caseContext struct {
	InitiatorSessionID uint16
	ResponderSessionID uint16
	InitiatorRandom    []byte
	ResponderRandom    []byte
	InitiatorEphKey    *ecdh.PrivateKey
	ResponderEphPubKey *ecdh.PublicKey
	InitiatorEphPubKey *ecdh.PublicKey
	ResponderEphKey    *ecdh.PrivateKey
	SharedSecret       []byte
	TranscriptHash     []byte
	Fabric             *Fabric
}

// generateSigma1 generates the Sigma1 Packet payload.
func (c *caseContext) generateSigma1() ([]byte, error) {
	var err error
	c.InitiatorEphKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	c.InitiatorRandom = make([]byte, 32)
	_, err = rand.Read(c.InitiatorRandom)
	if err != nil {
		return nil, err
	}

	if c.InitiatorSessionID == 0 {
		var id uint16
		if err := binary.Read(rand.Reader, binary.LittleEndian, &id); err == nil {
			c.InitiatorSessionID = id
		}
	}

	msg := caseSigma1{
		InitiatorRandom:    c.InitiatorRandom,
		InitiatorSessionID: c.InitiatorSessionID,
	}

	if c.Fabric != nil {
		ipk := c.Fabric.IPK()
		rootPub := c.Fabric.RootPublicKey()
		fabricID := c.Fabric.ID()
		nodeID := c.Fabric.NodeID()

		mac := hmac.New(sha256.New, ipk)
		mac.Write(c.InitiatorRandom)
		mac.Write(rootPub)
		binary.Write(mac, binary.LittleEndian, fabricID)
		binary.Write(mac, binary.LittleEndian, nodeID)
		msg.DestinationID = mac.Sum(nil)
	} else {
		msg.DestinationID = make([]byte, 32) // Placeholder if no fabric
	}

	msg.InitiatorEphPubKey = c.InitiatorEphKey.PublicKey().Bytes()
	payload := msg.Encode().Bytes()

	c.TranscriptHash = payload

	return payload, nil
}

// parseSigma1 processes the incoming Sigma1 message (Server side).
func (c *caseContext) parseSigma1(payload []byte) error {
	var msg caseSigma1
	var err error
	if err := msg.Decode(payload); err != nil {
		return err
	}
	c.InitiatorRandom = msg.InitiatorRandom
	c.InitiatorSessionID = msg.InitiatorSessionID
	c.InitiatorEphPubKey, err = ecdh.P256().NewPublicKey(msg.InitiatorEphPubKey)
	if err != nil {
		return err
	}
	c.TranscriptHash = payload
	return nil
}

// generateSigma2 generates the Sigma2 Packet payload (Server side).
func (c *caseContext) generateSigma2() ([]byte, error) {
	var err error
	c.ResponderEphKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	c.ResponderRandom = make([]byte, 32)
	_, err = rand.Read(c.ResponderRandom)
	if err != nil {
		return nil, err
	}

	c.SharedSecret, err = c.ResponderEphKey.ECDH(c.InitiatorEphPubKey)
	if err != nil {
		return nil, err
	}

	if c.Fabric == nil {
		return nil, fmt.Errorf("no fabric")
	}
	ipk := c.Fabric.IPK()
	salt := append(ipk, c.ResponderRandom...)
	salt = append(salt, c.ResponderEphKey.PublicKey().Bytes()...)
	salt = append(salt, c.TranscriptHash...)
	s2k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma2"), 16)

	cert, _ := c.Fabric.Certificate(c.Fabric.NodeID())
	noc := c.Fabric.SerializeCertificateIntoMatter(cert)

	// Generate Signature
	tbs := caseSigma2TBS{
		ResponderNOC:       noc,
		ResponderEphPubKey: c.ResponderEphKey.PublicKey().Bytes(),
	}
	privKey, err := c.Fabric.PrivateKey(c.Fabric.NodeID())
	if err != nil {
		return nil, err
	}
	signature, err := signTBS(privKey, tbs.Encode())
	if err != nil {
		return nil, err
	}

	// TBS 2 TBE transformation, stays inside the same binary, can get along with using a deterministic tlv lib.
	tbe := caseSigma2Signed{
		ResponderNOC: noc,
		Signature:    signature,
	}

	nonce := []byte("NCASE_Sigma2N")
	block, _ := aes.NewCipher(s2k)
	ccmMode, _ := ccm.NewCCM(block, 16, len(nonce))
	encrypted2 := ccmMode.Seal(nil, nonce, tbe.Encode().Bytes(), nil)

	msg := caseSigma2{
		ResponderRandom:    c.ResponderRandom,
		ResponderSessionID: c.ResponderSessionID,
		ResponderEphPubKey: c.ResponderEphKey.PublicKey().Bytes(),
		Encrypted:          encrypted2,
	}
	payload := msg.Encode().Bytes()
	c.TranscriptHash = append(c.TranscriptHash, payload...)

	return payload, nil
}

// parseSigma2 processes the incoming Sigma2 message from the responder and generates the Sigma3 payload.
func (c *caseContext) parseSigma2(payload []byte) ([]byte, uint16, error) {
	var msg caseSigma2
	if err := msg.Decode(payload); err != nil {
		return nil, 0, err
	}
	c.ResponderRandom = msg.ResponderRandom
	c.ResponderSessionID = msg.ResponderSessionID
	var err error
	c.ResponderEphPubKey, err = ecdh.P256().NewPublicKey(msg.ResponderEphPubKey)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid responder public key: %v", err)
	}

	c.SharedSecret, err = c.InitiatorEphKey.ECDH(c.ResponderEphPubKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ECDH failed: %v", err)
	}

	if c.Fabric == nil {
		return nil, 0, fmt.Errorf("fabric is required for IPK")
	}
	ipk := c.Fabric.IPK()
	salt := append(ipk, c.ResponderRandom...)
	salt = append(salt, c.ResponderEphPubKey.Bytes()...)
	salt = append(salt, c.TranscriptHash...) // TranscriptHash here is just Sigma1
	s2k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma2"), 16)

	nonce := []byte("NCASE_Sigma2N")
	block, err := aes.NewCipher(s2k)
	if err != nil {
		return nil, 0, err
	}
	ccmMode, err := ccm.NewCCM(block, 16, len(nonce))
	if err != nil {
		return nil, 0, err
	}
	_, err = ccmMode.Open(nil, nonce, msg.Encrypted, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt Sigma2: %v", err)
	}

	// Verify Signature
	tbe := caseSigma2Signed{}

	// Correcting the decryption flow:
	plaintext, err := ccmMode.Open(nil, nonce, msg.Encrypted, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt Sigma2: %v", err)
	}
	if err := tbe.Decode(plaintext); err != nil {
		return nil, 0, fmt.Errorf("failed to decode Sigma2Signed: %v", err)
	}

	// TBE -> TBS CAVEAT this is not the way to go. It MUST use the TBE bits as they were encoded.
	tbs := caseSigma2TBS{
		ResponderNOC:       tbe.ResponderNOC,
		ResponderICAC:      tbe.ResponderICAC,
		ResponderEphPubKey: c.ResponderEphPubKey.Bytes(),
		ResumptionID:       tbe.ResumptionID,
	}

	if err := verifySignature(tbe.ResponderNOC, tbs.Encode(), tbe.Signature); err != nil {
		return nil, 0, fmt.Errorf("invalid Sigma2 signature: %v", err)
	}

	c.TranscriptHash = append(c.TranscriptHash, payload...)

	return c.generateSigma3()
}

// parseSigma3 processes the incoming Sigma3 message (Server side).
func (c *caseContext) parseSigma3(payload []byte) ([]byte, error) {
	var msg caseSigma3
	if err := msg.Decode(payload); err != nil {
		return nil, err
	}

	ipk := c.Fabric.IPK()
	salt := append(ipk, c.TranscriptHash...)
	s3k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma3"), 16)

	nonce := []byte("NCASE_Sigma3N")
	block, _ := aes.NewCipher(s3k)
	ccmMode, _ := ccm.NewCCM(block, 16, len(nonce))
	plaintext, err := ccmMode.Open(nil, nonce, msg.Encrypted, nil)
	if err != nil {
		return nil, err
	}

	var tbe caseSigma3Signed
	if err := tbe.Decode(plaintext); err != nil {
		return nil, err
	}

	tbs := caseSigma3TBS{
		InitiatorNOC:       tbe.InitiatorNOC,
		InitiatorICAC:      tbe.InitiatorICAC,
		InitiatorEphPubKey: c.InitiatorEphPubKey.Bytes(),
		ResponderEphPubKey: c.ResponderEphKey.PublicKey().Bytes(),
	}
	if err := verifySignature(tbe.InitiatorNOC, tbs.Encode().Bytes(), tbe.Signature); err != nil {
		return nil, fmt.Errorf("invalid Sigma3 signature: %v", err)
	}

	c.TranscriptHash = append(c.TranscriptHash, payload...)

	sr := StatusReport{
		GeneralCode:  GeneralCodeSuccess,
		ProtocolID:   ProtocolIDSecureChannel,
		ProtocolCode: CodeSessionEstablishmentSuccess,
	}
	return sr.Encode(), nil
}

func (c *caseContext) generateSigma3() ([]byte, uint16, error) {
	var initiatorNOC, initiatorICAC, signature []byte
	if c.Fabric != nil {
		cert, err := c.Fabric.Certificate(c.Fabric.NodeID())
		if err != nil {
			return nil, 0, err
		}
		initiatorNOC = c.Fabric.SerializeCertificateIntoMatter(cert)

		privKey, err := c.Fabric.PrivateKey(c.Fabric.NodeID())
		if err != nil {
			return nil, 0, err
		}

		tbs := caseSigma3TBS{
			InitiatorNOC:       initiatorNOC,
			InitiatorICAC:      initiatorICAC,
			InitiatorEphPubKey: c.InitiatorEphKey.PublicKey().Bytes(),
			ResponderEphPubKey: c.ResponderEphPubKey.Bytes(),
		}
		signature, err = signTBS(privKey, tbs.Encode().Bytes())
		if err != nil {
			return nil, 0, err
		}
	}

	tbe := caseSigma3Signed{
		InitiatorNOC: initiatorNOC,
		Signature:    signature,
	}

	if c.Fabric == nil {
		return nil, 0, fmt.Errorf("fabric is required for IPK")
	}
	ipk := c.Fabric.IPK()
	salt := append(ipk, c.TranscriptHash...)
	s3k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma3"), 16)

	nonce := []byte("NCASE_Sigma3N")
	block, err := aes.NewCipher(s3k)
	if err != nil {
		return nil, 0, err
	}
	ccmMode, err := ccm.NewCCM(block, 16, len(nonce))
	if err != nil {
		return nil, 0, err
	}
	encrypted3 := ccmMode.Seal(nil, nonce, tbe.Encode().Bytes(), nil)

	msg := caseSigma3{Encrypted: encrypted3}
	payload := msg.Encode().Bytes()

	c.TranscriptHash = append(c.TranscriptHash, payload...)

	return payload, c.ResponderSessionID, nil
}

// sessionKeys derives the final application session keys after the handshake is complete.
func (c *caseContext) sessionKeys() (encryptionKey, decryptionKey []byte) {
	if c.Fabric == nil {
		return nil, nil
	}
	ipk := c.Fabric.IPK()
	salt := append(ipk, c.TranscriptHash...)
	keys := hkdfSha256(c.SharedSecret, salt, []byte("SessionKeys"), 48)

	return keys[:16], keys[16:32]
}

// Helper for HKDF
func hkdfSha256(secret, salt, info []byte, size int) []byte {
	engine := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, size)
	if _, err := io.ReadFull(engine, key); err != nil {
		return nil
	}
	return key
}

func signTBS(privKey any, data []byte) ([]byte, error) {
	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return nil, err
	}
	// Serialize (r, s) to 64 bytes (32 bytes each)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)
	return signature, nil
}

func verifySignature(noc []byte, data []byte, signature []byte) error {
	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length")
	}
	cert, err := ParseCertificateFromMatter(noc)
	if err != nil {
		return fmt.Errorf("failed to parse NOC: %v", err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	hash := sha256.Sum256(data)

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
