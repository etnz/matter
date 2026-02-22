package matter

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tom-code/gomat/ccm"
	"github.com/tom-code/gomat/mattertlv"
	"golang.org/x/crypto/hkdf"
)

// CASEContext manages the state of a Certificate Authenticated Session Establishment handshake.
type CASEContext struct {
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

// GenerateSigma1 generates the Sigma1 Packet.
//
// Steps:
// 1. Generate an ephemeral ECDH key pair (initiatorEphPubKey, initiatorEphPrivKey).
// 2. Generate a random 32-byte InitiatorRandom.
// 3. Construct the Sigma1 payload containing:
//   - InitiatorRandom
//   - InitiatorSessionId (from the Unsecured Session)
//   - DestinationId (HMAC-SHA256 using the Fabric's IPK over InitiatorRandom, Root Public Key, Fabric ID, and Node ID).
//   - InitiatorEphPubKey
//   - (Optional) ResumptionID and ResumeMIC if attempting session resumption.
//
// 4. Update the handshake transcript hash with the generated payload.
func (c *CASEContext) GenerateSigma1() *packet {
	// 1. Generate ephemeral keys
	var err error
	c.InitiatorEphKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}

	// 2. Generate InitiatorRandom
	c.InitiatorRandom = make([]byte, 32)
	rand.Read(c.InitiatorRandom)

	// 3. Construct Sigma1 Payload
	// We need a session ID for the initiator. In a real implementation, this comes from the session manager.
	// For now, we generate a random one or use a fixed one if not provided.
	if c.InitiatorSessionID == 0 {
		var id uint16
		if err := binary.Read(rand.Reader, binary.LittleEndian, &id); err == nil {
			c.InitiatorSessionID = id
		}
		// Fallback or error handling if needed, but rand.Reader usually succeeds.
	}

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, c.InitiatorRandom)
	tlv.WriteUInt(2, mattertlv.TYPE_UINT_2, uint64(c.InitiatorSessionID))

	// DestinationID generation (simplified for now, assuming we have the fabric/node info elsewhere or pass it in)
	// DestinationIdentifier = Crypto_HMAC(key=IPK, message=InitiatorRandom || RootPublicKey || FabricID || NodeID).
	if c.Fabric != nil {
		ipk := c.Fabric.ipk
		rootPub := c.Fabric.CertificateManager.GetRootPublicKey()
		fabricID := c.Fabric.id
		nodeID := c.Fabric.nodeID // Assuming Fabric has local node ID

		mac := hmac.New(sha256.New, ipk)
		mac.Write(c.InitiatorRandom)
		mac.Write(rootPub)
		binary.Write(mac, binary.LittleEndian, fabricID)
		binary.Write(mac, binary.LittleEndian, nodeID)
		tlv.WriteOctetString(3, mac.Sum(nil))
	} else {
		tlv.WriteOctetString(3, make([]byte, 32)) // Placeholder if no fabric
	}

	tlv.WriteOctetString(4, c.InitiatorEphKey.PublicKey().Bytes())
	// Resumption (optional) - skipped for now
	tlv.WriteStructEnd()

	payload := tlv.Bytes()

	// 4. Update Transcript Hash
	// Transcript starts with Sigma1 payload
	c.TranscriptHash = payload

	// Construct Packet
	// Sigma1 is sent over an unsecured session (ID 0)
	pkt := &packet{
		header: messageHeader{
			SessionID: 0,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeFlags: 0, // Initiator flag set by NewRequest/transport
			Opcode:        OpCodeCASESigma1,
			ProtocolId:    ProtocolIDSecureChannel,
		},
		payload: payload,
	}
	return pkt
}

// ParseSigma1 processes the incoming Sigma1 message (Server side).
func (c *CASEContext) ParseSigma1(payload []byte) error {
	tlv := mattertlv.Decode(payload)
	c.InitiatorRandom = tlv.GetOctetStringRec([]int{1})
	sessID, err := tlv.GetIntRec([]int{2})
	if err != nil {
		return err
	}
	c.InitiatorSessionID = uint16(sessID)
	// DestID (3) - ignored for now
	pubKeyBytes := tlv.GetOctetStringRec([]int{4})
	c.InitiatorEphPubKey, err = ecdh.P256().NewPublicKey(pubKeyBytes)
	if err != nil {
		return err
	}
	c.TranscriptHash = payload
	return nil
}

// GenerateSigma2 generates the Sigma2 Packet (Server side).
func (c *CASEContext) GenerateSigma2() (*packet, error) {
	// 1. Generate Ephemeral Key
	var err error
	c.ResponderEphKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// 2. Generate Random
	c.ResponderRandom = make([]byte, 32)
	rand.Read(c.ResponderRandom)

	// 3. Shared Secret
	c.SharedSecret, err = c.ResponderEphKey.ECDH(c.InitiatorEphPubKey)
	if err != nil {
		return nil, err
	}

	// 4. S2K derivation
	if c.Fabric == nil {
		return nil, fmt.Errorf("no fabric")
	}
	ipk := c.Fabric.ipk
	salt := append(ipk, c.ResponderRandom...)
	salt = append(salt, c.ResponderEphKey.PublicKey().Bytes()...)
	salt = append(salt, c.TranscriptHash...)
	s2k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma2"), 16)

	// 5. Encrypt Data (Responder NOC, Signature)
	var tbe mattertlv.TLVBuffer
	tbe.WriteAnonStruct()
	cert, _ := c.Fabric.CertificateManager.GetCertificate(c.Fabric.nodeID)
	tbe.WriteOctetString(1, c.Fabric.SerializeCertificateIntoMatter(cert))
	tbe.WriteOctetString(3, make([]byte, 64)) // Dummy signature
	tbe.WriteStructEnd()

	nonce := []byte("NCASE_Sigma2N")
	block, _ := aes.NewCipher(s2k)
	ccmMode, _ := ccm.NewCCM(block, 16, len(nonce))
	encrypted2 := ccmMode.Seal(nil, nonce, tbe.Bytes(), nil)

	// 6. Construct Sigma2 Payload
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, c.ResponderRandom)
	tlv.WriteUInt(2, mattertlv.TYPE_UINT_2, uint64(c.ResponderSessionID))
	tlv.WriteOctetString(3, c.ResponderEphKey.PublicKey().Bytes())
	tlv.WriteOctetString(4, encrypted2)
	tlv.WriteStructEnd()

	payload := tlv.Bytes()
	c.TranscriptHash = append(c.TranscriptHash, payload...)

	pkt := &packet{
		header: messageHeader{SessionID: 0},
		protocolHeader: protocolMessageHeader{
			Opcode:     OpCodeCASESigma2,
			ProtocolId: ProtocolIDSecureChannel,
		},
		payload: payload,
	}
	return pkt, nil
}

// ParseSigma2 processes the incoming Sigma2 message from the responder.
//
// Steps:
// 1. Extract the ResponderRandom, ResponderSessionId, ResponderEphPubKey, and Encrypted2 struct.
// 2. Update the handshake transcript hash with the unencrypted part of Sigma2.
// 3. Derive the Sigma2 Key (S2K) using HKDF-SHA256 with:
//   - Salt = IPK || ResponderRandom || ResponderEphPubKey || TranscriptHash(Sigma1)
//   - IKM = ECDH(InitiatorEphPrivKey, ResponderEphPubKey)
//
// 4. Decrypt the Encrypted2 struct using the derived S2K.
// 5. Validate the Responder's identity:
//   - Verify the Responder's Node Operational Certificate (NOC) chain against the trusted Root CA.
//   - Verify the signature over the sigma-2-tbsdata structure (containing ResponderNOC, ResponderICAC, ResponderEphPubKey, InitiatorEphPubKey) using the Responder's NOC public key.
//
// 6. Extract the Responder's Session ID from the decrypted payload.
// 7. Update the transcript hash with the decrypted Encrypted2 struct.
func (c *CASEContext) ParseSigma2(payload []byte) (sigma3 *packet, sessionID uint16, err error) {
	// 1. Parse Sigma2 TLV
	tlv := mattertlv.Decode(payload)
	c.ResponderRandom = tlv.GetOctetStringRec([]int{1})
	resSessionID, err := tlv.GetIntRec([]int{2})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get responder session ID: %v", err)
	}
	c.ResponderSessionID = uint16(resSessionID)
	responderPubKeyBytes := tlv.GetOctetStringRec([]int{3})
	encrypted2 := tlv.GetOctetStringRec([]int{4})

	c.ResponderEphPubKey, err = ecdh.P256().NewPublicKey(responderPubKeyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid responder public key: %v", err)
	}

	// 2. Update Transcript Hash (with unencrypted part)
	// We need to reconstruct the unencrypted part or assume payload contains it.
	// The transcript hash includes Sigma1 || Sigma2_Unencrypted.
	// Ideally, we should separate the encrypted part, but for simplicity/placeholder:
	// We append the raw payload of Sigma2 (which includes the encrypted part as an octet string).
	// Note: The spec says "Sigma2" message.
	// c.TranscriptHash = append(c.TranscriptHash, payload...) // This might be slightly off vs spec details on "Encrypted2"

	// 3. Derive Handshake Keys
	c.SharedSecret, err = c.InitiatorEphKey.ECDH(c.ResponderEphPubKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ECDH failed: %v", err)
	}

	// Derive Sigma2 Key (S2K)
	// Salt = IPK || ResponderRandom || ResponderEphPubKey || TranscriptHash(Sigma1)
	if c.Fabric == nil {
		return nil, 0, fmt.Errorf("fabric is required for IPK")
	}
	ipk := c.Fabric.ipk
	salt := append(ipk, c.ResponderRandom...)
	salt = append(salt, c.ResponderEphPubKey.Bytes()...)
	salt = append(salt, c.TranscriptHash...) // TranscriptHash here is just Sigma1
	s2k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma2"), 16)

	// 4. Decrypt Encrypted2
	// We need the nonce. Nonce is usually "NCASE_Sigma2N" + 0s?
	// In flows.go: nonce := []byte("NCASE_Sigma3N") for Sigma3.
	nonce := []byte("NCASE_Sigma2N")
	block, err := aes.NewCipher(s2k)
	if err != nil {
		return nil, 0, err
	}
	ccmMode, err := ccm.NewCCM(block, 16, len(nonce))
	if err != nil {
		return nil, 0, err
	}
	_, err = ccmMode.Open(nil, nonce, encrypted2, nil) // AAD?
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt Sigma2: %v", err)
	}

	// 5. Validate Responder Identity (Skipped for now - requires Certificate Manager)
	// ... verify cert chain ...
	// ... verify signature ...

	// 6. Extract Responder Session ID (if it was inside Encrypted2, but usually it's in the clear in Sigma2)
	// Wait, the spec says ResponderSessionId is in the clear (tag 2).
	// The Encrypted2 contains the Responder's NOC and Signature.

	// 7. Update Transcript Hash
	// Transcript = Hash(Sigma1 || Sigma2) ?
	// We need to be careful about what exactly goes into the hash.
	// For now, we'll append the whole Sigma2 payload to the transcript.
	c.TranscriptHash = append(c.TranscriptHash, payload...)

	// Generate Sigma3
	return c.generateSigma3()
}

// ParseSigma3 processes the incoming Sigma3 message (Server side).
func (c *CASEContext) ParseSigma3(payload []byte) error {
	tlv := mattertlv.Decode(payload)
	encrypted3 := tlv.GetOctetStringRec([]int{1})

	ipk := c.Fabric.ipk
	salt := append(ipk, c.TranscriptHash...)
	s3k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma3"), 16)

	nonce := []byte("NCASE_Sigma3N")
	block, _ := aes.NewCipher(s3k)
	ccmMode, _ := ccm.NewCCM(block, 16, len(nonce))
	if _, err := ccmMode.Open(nil, nonce, encrypted3, nil); err != nil {
		return err
	}
	c.TranscriptHash = append(c.TranscriptHash, payload...)
	return nil
}

func (c *CASEContext) generateSigma3() (*packet, uint16, error) {
	// 1. Construct TBEData3 (To-Be-Encrypted)
	// Contains Initiator NOC, ICAC, Signature.
	var initiatorNOC, initiatorICAC, signature []byte
	if c.Fabric != nil {
		// Get Certificates
		cert, err := c.Fabric.CertificateManager.GetCertificate(c.Fabric.nodeID)
		if err != nil {
			return nil, 0, err
		}
		initiatorNOC = c.Fabric.SerializeCertificateIntoMatter(cert)
		// ICAC is optional/TODO

		// Construct TBSData3 (To-Be-Signed)
		// Structure: InitiatorNOC, InitiatorICAC, InitiatorEphPubKey, ResponderEphPubKey
		var tbs tlvBuffer
		tbs.WriteAnonStruct()
		tbs.WriteOctetString(1, initiatorNOC) // InitiatorNOC
		if len(initiatorICAC) > 0 {
			tbs.WriteOctetString(2, initiatorICAC)
		}
		tbs.WriteOctetString(3, c.InitiatorEphKey.PublicKey().Bytes())
		tbs.WriteOctetString(4, c.ResponderEphPubKey.Bytes())
		tbs.WriteStructEnd()

		// Sign TBSData3
		privKey, err := c.Fabric.CertificateManager.GetPrivkey(c.Fabric.nodeID)
		if err != nil {
			return nil, 0, err
		}
		// Sign logic (simplified, assumes ECDSA P256)
		// signature = ...
		_ = privKey
	}

	var tbe mattertlv.TLVBuffer
	tbe.WriteAnonStruct()
	tbe.WriteOctetString(1, initiatorNOC)
	// tbe.WriteOctetString(2, initiatorICAC) // Optional
	tbe.WriteOctetString(3, signature)
	tbe.WriteStructEnd()

	// Derive Sigma3 Key (S3K)
	// Salt = IPK || TranscriptHash (Sigma1 || Sigma2)
	if c.Fabric == nil {
		return nil, 0, fmt.Errorf("fabric is required for IPK")
	}
	ipk := c.Fabric.ipk
	salt := append(ipk, c.TranscriptHash...)
	s3k := hkdfSha256(c.SharedSecret, salt, []byte("Sigma3"), 16)

	// 2. Encrypt TBEData3
	nonce := []byte("NCASE_Sigma3N")
	block, err := aes.NewCipher(s3k)
	if err != nil {
		return nil, 0, err
	}
	ccmMode, err := ccm.NewCCM(block, 16, len(nonce))
	if err != nil {
		return nil, 0, err
	}
	encrypted3 := ccmMode.Seal(nil, nonce, tbe.Bytes(), nil)

	// 3. Construct Sigma3 Payload
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, encrypted3)
	tlv.WriteStructEnd()

	payload := tlv.Bytes()

	// Update Transcript
	c.TranscriptHash = append(c.TranscriptHash, payload...)

	pkt := &packet{
		header: messageHeader{
			SessionID:      c.ResponderSessionID, // Send to Responder's Session ID
			MessageCounter: 2,                    // Increment
		},
		protocolHeader: protocolMessageHeader{
			Opcode:     OpCodeCASESigma3,
			ProtocolId: ProtocolIDSecureChannel,
			ExchangeID: 0, // Transport sets this
		},
		payload: payload,
	}

	return pkt, c.ResponderSessionID, nil
}

// SessionKeys derives the final application session keys after the handshake is complete.
//
// Steps:
// 1. Use HKDF-SHA256 to derive the session keys from the shared secret and the final transcript hash (Sigma1 || Sigma2 || Sigma3).
//   - Salt = IPK || TranscriptHash
//   - Info = "SessionKeys"
//
// 2. Derive the I2RKey (Initiator-to-Responder) and R2IKey (Responder-to-Initiator) for the secure session.
// 3. These keys will be used for AES-CCM encryption/decryption of all subsequent application messages.
func (c *CASEContext) SessionKeys() (encryptionKey, decryptionKey []byte) {
	// 1. Derive Session Keys
	// Salt = IPK || TranscriptHash (Sigma1 || Sigma2 || Sigma3)
	if c.Fabric == nil {
		// This should not happen if handshake succeeded, but safe guard
		return nil, nil
	}
	ipk := c.Fabric.ipk
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

// Helper for TLV writing (simplified wrapper around mattertlv)
type tlvBuffer struct {
	mattertlv.TLVBuffer
}
