package matter // PASEContext manages the state of a Passcode-Authenticated Session Establishment handshake.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"filippo.io/nistec"
	"github.com/tom-code/gomat/mattertlv"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// TODO: dependencies to the mattertvl indicates that we are doing dynamic TLV parsing inside this file. We should consider defining static structs for the messages and using a more static approach to TLV encoding/decoding instead of dynamic parsing. This would be more efficient and less error-prone, but requires more upfront struct definitions and encoding/decoding logic.

// PASE is used exclusively during the commissioning phase to securely establish the first session.
type PASEContext struct {
	// user provided passcode from QR Code usually but any means also works.
	Passcode uint32
	// Internal state: SPAKE2+ context, transcript hashes, derived shared secrets, etc.
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	ResponderSessionID uint16
	PasscodeID         uint16
	ExchangeID         uint16

	PBKDFParamRequest  []byte
	PBKDFParamResponse []byte

	w0, w1 *big.Int
	x      []byte
	pA     []byte // pA
	pB     []byte // pB
	Ke     []byte
	cA     []byte
}

var (
	p256P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	p256N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
)

// GeneratePBKDFParamRequest generates the initial PASE message (Initiator).
//
// Steps:
// 1. Generate a random 32-byte InitiatorRandom using Crypto_DRBG.
// 2. Generate a fresh InitiatorSessionId for the Unsecured Session context.
// 3. Choose a PasscodeId (0 for default commissioning passcode).
// 4. Construct the PBKDFParamRequest payload.
func (c *PASEContext) GeneratePBKDFParamRequest() *packet {
	c.InitiatorRandom = make([]byte, 32)
	rand.Read(c.InitiatorRandom)

	if c.InitiatorSessionID == 0 {
		var id uint16
		binary.Read(rand.Reader, binary.LittleEndian, &id)
		c.InitiatorSessionID = id
	}
	if c.ExchangeID == 0 {
		var id uint16
		binary.Read(rand.Reader, binary.LittleEndian, &id)
		c.ExchangeID = id
	}

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, c.InitiatorRandom)
	tlv.WriteUInt(2, mattertlv.TYPE_UINT_2, uint64(c.InitiatorSessionID))
	tlv.WriteUInt(3, mattertlv.TYPE_UINT_2, uint64(c.PasscodeID)) // 0
	tlv.WriteBool(4, false)                                       // hasPBKDFParameters
	tlv.WriteStructEnd()

	c.PBKDFParamRequest = tlv.Bytes()

	return &packet{
		header: messageHeader{
			SessionID: 0,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeFlags: FlagInitiator | FlagReliable,
			Opcode:        OpCodePBKDFParamRequest,
			ProtocolId:    ProtocolIDSecureChannel,
			ExchangeID:    c.ExchangeID,
		},
		payload: c.PBKDFParamRequest,
	}
}

// ParsePBKDFParamResponseAndGeneratePake1 processes the server's PBKDF parameters and sends Pake1.
//
// Steps:
// 1. Extract ResponderRandom, ResponderSessionId, and PBKDFParameters (Salt, Iterations) from the response.
// 2. Generate Crypto_PAKEValues_Initiator (w0, w1) using PBKDF2 with the out-of-band Passcode, Salt, and Iterations.
// 3. Generate the Initiator's ephemeral public key (pA) using the SPAKE2+ algorithm.
// 4. Construct the Pake1 message containing pA.
func (c *PASEContext) ParsePBKDFParamResponseAndGeneratePake1(payload []byte) (pake1 *packet, err error) {
	c.PBKDFParamResponse = payload
	tlv := mattertlv.Decode(payload)
	// InitiatorRandom (1) - not used in calculation but extracted
	_ = tlv.GetOctetStringRec([]int{1})
	resSessionID, err := tlv.GetIntRec([]int{3})
	if err != nil {
		return nil, fmt.Errorf("failed to get responder session ID: %v", err)
	}
	c.ResponderSessionID = uint16(resSessionID)

	// PBKDFParameters (4) -> Iterations (1), Salt (2)
	iterations, err := tlv.GetIntRec([]int{4, 1})
	if err != nil {
		return nil, fmt.Errorf("failed to get iterations: %v", err)
	}
	salt := tlv.GetOctetStringRec([]int{4, 2})

	// Derive w0, w1
	passcodeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(passcodeBytes, c.Passcode)

	ws := pbkdf2.Key(passcodeBytes, salt, int(iterations), 80, sha256.New)
	w0s := ws[:40]
	w1s := ws[40:]

	p := p256P
	c.w0 = new(big.Int).SetBytes(w0s)
	c.w0.Mod(c.w0, p)
	c.w1 = new(big.Int).SetBytes(w1s)
	c.w1.Mod(c.w1, p)

	// Generate pA = x*G + w0*M
	// M point for P256 (uncompressed) defined in Matter Spec Section 3.9. SPAKE2+
	mBytes, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	M, err := nistec.NewP256Point().SetBytes(mBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid M point: %v", err)
	}

	// Ephemeral private key x
	// Use crypto/ecdh to generate the key to avoid deprecated elliptic.GenerateKey
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	c.x = ecdhKey.Bytes()
	pubKeyBytes := ecdhKey.PublicKey().Bytes()
	xG, err := nistec.NewP256Point().SetBytes(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %v", err)
	}
	// x*G is (x, y) returned by GenerateKey

	// w0*M
	w0M, err := nistec.NewP256Point().ScalarMult(M, c.w0.Bytes())
	if err != nil {
		return nil, fmt.Errorf("scalar mult failed: %v", err)
	}

	// pA = x*G + w0*M
	pA := nistec.NewP256Point().Add(xG, w0M)
	c.pA = pA.Bytes()

	var tlvOut mattertlv.TLVBuffer
	tlvOut.WriteAnonStruct()
	tlvOut.WriteOctetString(1, c.pA)
	tlvOut.WriteStructEnd()

	return &packet{
		header: messageHeader{
			SessionID: 0,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeFlags: FlagInitiator | FlagReliable,
			Opcode:        OpCodePASEPake1,
			ProtocolId:    ProtocolIDSecureChannel,
			ExchangeID:    c.ExchangeID,
		},
		payload: tlvOut.Bytes(),
	}, nil
}

// ParsePake2AndGeneratePake3 processes the server's Pake2 message and completes the SPAKE2+ handshake.
//
// Steps:
//  1. Extract the Responder's public key (pB) and confirmation hash (cB).
//  2. Compute the handshake transcript hash (TT) using PBKDFParamRequest, PBKDFParamResponse, pA, and pB.
//  3. Compute the Initiator's confirmation hash (cA), the expected Responder confirmation hash (expected_cB),
//     and the shared secret (Ke) via Crypto_P2(TT, pA, pB).
//  4. Verify that the received cB matches expected_cB. If verification fails, abort.
//  5. Construct the Pake3 message containing the Initiator's confirmation hash (cA).
func (c *PASEContext) ParsePake2AndGeneratePake3(payload []byte) (pake3 *packet, sessionID uint16, err error) {
	tlv := mattertlv.Decode(payload)
	pBBytes := tlv.GetOctetStringRec([]int{1})
	cB := tlv.GetOctetStringRec([]int{2})

	pB, err := nistec.NewP256Point().SetBytes(pBBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pB point: %v", err)
	}
	c.pB = pB.Bytes()

	// Compute TT
	contextHash := sha256.Sum256(append([]byte("CHIP PAKE V1 Commissioning"), append(c.PBKDFParamRequest, c.PBKDFParamResponse...)...))

	// Z = x*(pB - w0*N)
	// N point for P256 (uncompressed) defined in Matter Spec Section 3.9. SPAKE2+
	nBytes, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	N, err := nistec.NewP256Point().SetBytes(nBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid N point: %v", err)
	}

	// Calculate -w0 mod N
	w0Mod := new(big.Int).Mod(c.w0, p256N)
	w0Neg := new(big.Int).Sub(p256N, w0Mod)
	w0Neg.Mod(w0Neg, p256N)

	// -w0*N
	w0NegN, err := nistec.NewP256Point().ScalarMult(N, bigIntTo32Bytes(w0Neg))
	if err != nil {
		return nil, 0, fmt.Errorf("scalar mult failed: %v", err)
	}

	// temp = pB + (-w0*N)
	temp := nistec.NewP256Point().Add(pB, w0NegN)

	// Z = x * temp
	Z, _ := nistec.NewP256Point().ScalarMult(temp, c.x)

	// V = w1 * temp
	V, _ := nistec.NewP256Point().ScalarMult(temp, c.w1.Bytes())

	// TT construction
	tt := make([]byte, 0)
	tt = appendLengthAndValue(tt, contextHash[:])
	tt = appendLengthAndValue(tt, c.pA)                  // pA
	tt = appendLengthAndValue(tt, c.pB)                  // pB
	tt = appendLengthAndValue(tt, Z.Bytes())             // Z
	tt = appendLengthAndValue(tt, V.Bytes())             // V
	tt = appendLengthAndValue(tt, bigIntTo32Bytes(c.w0)) // w0

	// Crypto_P2(TT, pA, pB) -> cA, cB, Ke
	// Ka = SHA256(TT)
	ka := sha256.Sum256(tt)
	c.Ke = ka[:16]
	kcA := ka[16:32]
	kcB := ka[16:32]

	macA := hmac.New(sha256.New, kcA)
	macA.Write(c.pB)
	cA := macA.Sum(nil)

	macB := hmac.New(sha256.New, kcB)
	macB.Write(c.pA)
	expectedCB := macB.Sum(nil)

	if !hmac.Equal(cB, expectedCB) {
		return nil, 0, fmt.Errorf("invalid cB confirmation")
	}

	var tlvOut mattertlv.TLVBuffer
	tlvOut.WriteAnonStruct()
	tlvOut.WriteOctetString(1, cA)
	tlvOut.WriteStructEnd()

	return &packet{
		header: messageHeader{
			SessionID: 0,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeFlags: FlagInitiator | FlagReliable,
			Opcode:        OpCodePASEPake3,
			ProtocolId:    ProtocolIDSecureChannel,
			ExchangeID:    c.ExchangeID,
		},
		payload: tlvOut.Bytes(),
	}, c.ResponderSessionID, nil
}

// SessionKeys derives the final application session keys after Pake3 is successfully sent/verified.
//
// Steps:
// 1. Use HKDF-SHA256 to derive the keys from the SPAKE2+ shared secret (Ke).
//   - Salt = [] (empty array)
//   - Info = "SessionKeys"
//
// 2. Derive I2RKey, R2IKey, and the AttestationChallenge (used later in Device Attestation).
// 3. These keys will be used for AES-CCM encryption/decryption of the subsequent commissioning messages.
func (c *PASEContext) SessionKeys() (encryptionKey, decryptionKey, attestationChallenge []byte) {
	salt := []byte{}
	info := []byte("SessionKeys")

	kdf := hkdf.New(sha256.New, c.Ke, salt, info)
	keys := make([]byte, 48)
	io.ReadFull(kdf, keys)

	return keys[:16], keys[16:32], keys[32:]
}

func (c *PASEContext) ParsePBKDFParamRequest(payload []byte) error {
	tlv := mattertlv.Decode(payload)
	c.InitiatorRandom = tlv.GetOctetStringRec([]int{1})
	sessID, err := tlv.GetIntRec([]int{2})
	if err != nil {
		return fmt.Errorf("failed to get initiator session ID: %v", err)
	}
	c.InitiatorSessionID = uint16(sessID)
	passcodeID, err := tlv.GetIntRec([]int{3})
	if err != nil {
		return fmt.Errorf("failed to get passcode ID: %v", err)
	}
	c.PasscodeID = uint16(passcodeID)
	c.PBKDFParamRequest = payload
	return nil
}

func (c *PASEContext) GeneratePBKDFParamResponse() (*packet, error) {
	// Responder Random
	responderRandom := make([]byte, 32)
	rand.Read(responderRandom)

	// PBKDF Parameters
	iterations := uint32(1000) // Standard default
	salt := make([]byte, 16)
	rand.Read(salt)

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, c.InitiatorRandom)
	tlv.WriteOctetString(2, responderRandom)
	tlv.WriteUInt(3, mattertlv.TYPE_UINT_2, uint64(c.ResponderSessionID))
	tlv.WriteStruct(4)
	tlv.WriteUInt(1, mattertlv.TYPE_UINT_4, uint64(iterations))
	tlv.WriteOctetString(2, salt)
	tlv.WriteStructEnd()
	tlv.WriteStructEnd()

	c.PBKDFParamResponse = tlv.Bytes()

	return &packet{
		header: messageHeader{SessionID: 0},
		protocolHeader: protocolMessageHeader{
			Opcode:     OpCodePBKDFParamResponse,
			ProtocolId: ProtocolIDSecureChannel,
		},
		payload: c.PBKDFParamResponse,
	}, nil
}

func (c *PASEContext) ParsePake1AndGeneratePake2(payload []byte) (*packet, error) {
	tlv := mattertlv.Decode(payload)
	pABytes := tlv.GetOctetStringRec([]int{1})
	pA, err := nistec.NewP256Point().SetBytes(pABytes)
	if err != nil {
		return nil, fmt.Errorf("invalid pA point: %v", err)
	}
	c.pA = pABytes

	// Re-parse PBKDF params from our own response to calculate w0, w1
	tlvResp := mattertlv.Decode(c.PBKDFParamResponse)
	iterations, _ := tlvResp.GetIntRec([]int{4, 1})
	salt := tlvResp.GetOctetStringRec([]int{4, 2})

	passcodeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(passcodeBytes, c.Passcode)
	ws := pbkdf2.Key(passcodeBytes, salt, int(iterations), 80, sha256.New)
	w0s := ws[:40]
	w1s := ws[40:]

	p := p256P
	c.w0 = new(big.Int).SetBytes(w0s)
	c.w0.Mod(c.w0, p)
	c.w1 = new(big.Int).SetBytes(w1s)
	c.w1.Mod(c.w1, p)

	// Generate y (ephemeral key)
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	y := ecdhKey.Bytes()
	c.x = y // Store y in x field

	// y*G
	yG, err := nistec.NewP256Point().SetBytes(ecdhKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	// N point
	nBytes, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	N, err := nistec.NewP256Point().SetBytes(nBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid N point: %v", err)
	}

	// w0*N
	w0N, err := nistec.NewP256Point().ScalarMult(N, c.w0.Bytes())
	if err != nil {
		return nil, err
	}

	// pB = y*G + w0*N
	pB := nistec.NewP256Point().Add(yG, w0N)
	c.pB = pB.Bytes()

	// Calculate TT
	contextHash := sha256.Sum256(append([]byte("CHIP PAKE V1 Commissioning"), append(c.PBKDFParamRequest, c.PBKDFParamResponse...)...))

	// M point
	mBytes, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	M, err := nistec.NewP256Point().SetBytes(mBytes)
	if err != nil {
		return nil, err
	}

	// Z = y*(pA - w0*M)
	// Calculate -w0 mod N
	w0Mod := new(big.Int).Mod(c.w0, p256N)
	w0Neg := new(big.Int).Sub(p256N, w0Mod)
	w0Neg.Mod(w0Neg, p256N)

	w0NegM, _ := nistec.NewP256Point().ScalarMult(M, bigIntTo32Bytes(w0Neg))
	temp := nistec.NewP256Point().Add(pA, w0NegM)
	Z, _ := nistec.NewP256Point().ScalarMult(temp, y)

	// V = y*L where L = w1*G. Since we don't have L, we compute V = w1*(y*G) = w1*yG
	V, _ := nistec.NewP256Point().ScalarMult(yG, c.w1.Bytes())

	tt := make([]byte, 0)
	tt = appendLengthAndValue(tt, contextHash[:])
	tt = appendLengthAndValue(tt, c.pA)
	tt = appendLengthAndValue(tt, c.pB)
	tt = appendLengthAndValue(tt, Z.Bytes())
	tt = appendLengthAndValue(tt, V.Bytes())
	tt = appendLengthAndValue(tt, bigIntTo32Bytes(c.w0))

	ka := sha256.Sum256(tt)
	c.Ke = ka[:16]
	kcA := ka[16:32]
	kcB := ka[16:32]

	macA := hmac.New(sha256.New, kcA)
	macA.Write(c.pB)
	c.cA = macA.Sum(nil)

	macB := hmac.New(sha256.New, kcB)
	macB.Write(c.pA)
	cB := macB.Sum(nil)

	var tlvOut mattertlv.TLVBuffer
	tlvOut.WriteAnonStruct()
	tlvOut.WriteOctetString(1, c.pB)
	tlvOut.WriteOctetString(2, cB)
	tlvOut.WriteStructEnd()

	return &packet{
		header: messageHeader{SessionID: 0},
		protocolHeader: protocolMessageHeader{
			Opcode:     OpCodePASEPake2,
			ProtocolId: ProtocolIDSecureChannel,
		},
		payload: tlvOut.Bytes(),
	}, nil
}

func (c *PASEContext) ParsePake3(payload []byte) error {
	tlv := mattertlv.Decode(payload)
	cA := tlv.GetOctetStringRec([]int{1})

	if !hmac.Equal(cA, c.cA) {
		return fmt.Errorf("invalid cA confirmation")
	}
	return nil
}

func appendLengthAndValue(buf []byte, val []byte) []byte {
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(len(val)))
	buf = append(buf, lenBytes...)
	buf = append(buf, val...)
	return buf
}

func bigIntTo32Bytes(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) < 32 {
		pad := make([]byte, 32-len(b))
		return append(pad, b...)
	}
	return b
}
