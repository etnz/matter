package securechannel

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
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// PASE is used exclusively during the commissioning phase to securely establish the first session.
//
// PASEContext manages the state of a Passcode-Authenticated Session Establishment handshake.
// It is handled separately from CASE since it has a different flow and message structure, and is only used during commissioning.
// There is one CASE context per session, while there may be multiple PASE contexts during commissioning (e.g. if the first attempt fails and the commissioner retries with a different passcode).
// So the PASEContext is stored by ExchangeID.
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

// NewPASEContextFromPBKDFParamRequest creates a new PASEContext for a responder, parses the request payload,
// sets the responder session ID, and generates the PBKDFParamResponse payload.
func NewPASEContextFromPBKDFParamRequest(passcode uint32, requestPayload []byte) (*PASEContext, []byte, error) {
	paseCtx := &PASEContext{Passcode: passcode}
	if err := paseCtx.ParsePBKDFParamRequest(requestPayload); err != nil {
		return nil, nil, err
	}

	var newSessionID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &newSessionID)
	paseCtx.ResponderSessionID = newSessionID

	payload, err := paseCtx.GeneratePBKDFParamResponse()
	if err != nil {
		return nil, nil, err
	}
	return paseCtx, payload, nil
}

// GeneratePBKDFParamRequest generates the initial PASE message payload (Initiator).
func (c *PASEContext) GeneratePBKDFParamRequest() ([]byte, error) {
	c.InitiatorRandom = make([]byte, 32)
	_, err := rand.Read(c.InitiatorRandom)
	if err != nil {
		return nil, err
	}

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

	req := pbkdfParamRequest{
		InitiatorRandom:    c.InitiatorRandom,
		InitiatorSessionID: c.InitiatorSessionID,
		PasscodeID:         c.PasscodeID,
	}
	c.PBKDFParamRequest = req.Encode().Bytes()

	return c.PBKDFParamRequest, nil
}

// ParsePBKDFParamResponseAndGeneratePake1 processes the server's PBKDF parameters and generates the Pake1 payload.
func (c *PASEContext) ParsePBKDFParamResponseAndGeneratePake1(payload []byte) ([]byte, error) {
	c.PBKDFParamResponse = payload
	var resp pbkdfParamResponse
	if err := resp.Decode(payload); err != nil {
		return nil, err
	}
	c.ResponderSessionID = resp.ResponderSessionID

	if resp.PBKDFParameters == nil {
		return nil, fmt.Errorf("missing PBKDF parameters")
	}
	iterations := resp.PBKDFParameters.Iterations
	salt := resp.PBKDFParameters.Salt

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

	mBytes, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	M, err := nistec.NewP256Point().SetBytes(mBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid M point: %v", err)
	}

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

	w0M, err := nistec.NewP256Point().ScalarMult(M, c.w0.Bytes())
	if err != nil {
		return nil, fmt.Errorf("scalar mult failed: %v", err)
	}

	pA := nistec.NewP256Point().Add(xG, w0M)
	c.pA = pA.Bytes()

	pake1Msg := pake1{PA: c.pA}

	return pake1Msg.Encode().Bytes(), nil
}

// ParsePake2AndGeneratePake3 processes the server's Pake2 message and generates the Pake3 payload.
func (c *PASEContext) ParsePake2AndGeneratePake3(payload []byte) ([]byte, uint16, error) {
	var msg pake2
	if err := msg.Decode(payload); err != nil {
		return nil, 0, err
	}
	pB, err := nistec.NewP256Point().SetBytes(msg.PB)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pB point: %v", err)
	}
	c.pB = pB.Bytes()

	contextHash := sha256.Sum256(append([]byte("CHIP PAKE V1 Commissioning"), append(c.PBKDFParamRequest, c.PBKDFParamResponse...)...))

	nBytes, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	N, err := nistec.NewP256Point().SetBytes(nBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid N point: %v", err)
	}

	w0Mod := new(big.Int).Mod(c.w0, p256N)
	w0Neg := new(big.Int).Sub(p256N, w0Mod)
	w0Neg.Mod(w0Neg, p256N)

	w0NegN, err := nistec.NewP256Point().ScalarMult(N, bigIntTo32Bytes(w0Neg))
	if err != nil {
		return nil, 0, fmt.Errorf("scalar mult failed: %v", err)
	}

	temp := nistec.NewP256Point().Add(pB, w0NegN)

	Z, _ := nistec.NewP256Point().ScalarMult(temp, c.x)

	V, _ := nistec.NewP256Point().ScalarMult(temp, c.w1.Bytes())

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
	cA := macA.Sum(nil)

	macB := hmac.New(sha256.New, kcB)
	macB.Write(c.pA)
	expectedCB := macB.Sum(nil)

	if !hmac.Equal(msg.CB, expectedCB) {
		return nil, 0, fmt.Errorf("invalid cB confirmation")
	}

	pake3Msg := pake3{CA: cA}

	return pake3Msg.Encode().Bytes(), c.ResponderSessionID, nil
}

// SessionKeys derives the final application session keys.
func (c *PASEContext) SessionKeys() (encryptionKey, decryptionKey, attestationChallenge []byte) {
	salt := []byte{}
	info := []byte("SessionKeys")

	kdf := hkdf.New(sha256.New, c.Ke, salt, info)
	keys := make([]byte, 48)
	io.ReadFull(kdf, keys)

	return keys[:16], keys[16:32], keys[32:]
}

func (c *PASEContext) ParsePBKDFParamRequest(payload []byte) error {
	var req pbkdfParamRequest
	if err := req.Decode(payload); err != nil {
		return err
	}

	var newSessionID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &newSessionID)
	c.ResponderSessionID = newSessionID

	c.InitiatorSessionID = req.InitiatorSessionID
	c.PasscodeID = req.PasscodeID
	c.PBKDFParamRequest = payload
	return nil
}

func (c *PASEContext) GeneratePBKDFParamResponse() ([]byte, error) {
	responderRandom := make([]byte, 32)
	_, err := rand.Read(responderRandom)
	if err != nil {
		return nil, err
	}

	iterations := uint32(1000)
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	resp := pbkdfParamResponse{
		InitiatorRandom:    c.InitiatorRandom,
		ResponderRandom:    responderRandom,
		ResponderSessionID: c.ResponderSessionID,
		PBKDFParameters: &pbkdfParameters{
			Iterations: iterations,
			Salt:       salt,
		},
	}

	c.PBKDFParamResponse = resp.Encode().Bytes()

	return c.PBKDFParamResponse, nil
}

func (c *PASEContext) ParsePake1AndGeneratePake2(payload []byte) ([]byte, error) {
	var msg pake1
	if err := msg.Decode(payload); err != nil {
		return nil, err
	}
	pA, err := nistec.NewP256Point().SetBytes(msg.PA)
	if err != nil {
		return nil, fmt.Errorf("invalid pA point: %v", err)
	}
	c.pA = msg.PA

	var resp pbkdfParamResponse
	if err := resp.Decode(c.PBKDFParamResponse); err != nil {
		return nil, err
	}
	iterations := resp.PBKDFParameters.Iterations
	salt := resp.PBKDFParameters.Salt

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

	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	y := ecdhKey.Bytes()
	c.x = y

	yG, err := nistec.NewP256Point().SetBytes(ecdhKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	nBytes, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	N, err := nistec.NewP256Point().SetBytes(nBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid N point: %v", err)
	}

	w0N, err := nistec.NewP256Point().ScalarMult(N, c.w0.Bytes())
	if err != nil {
		return nil, err
	}

	pB := nistec.NewP256Point().Add(yG, w0N)
	c.pB = pB.Bytes()

	contextHash := sha256.Sum256(append([]byte("CHIP PAKE V1 Commissioning"), append(c.PBKDFParamRequest, c.PBKDFParamResponse...)...))

	mBytes, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	M, err := nistec.NewP256Point().SetBytes(mBytes)
	if err != nil {
		return nil, err
	}

	w0Mod := new(big.Int).Mod(c.w0, p256N)
	w0Neg := new(big.Int).Sub(p256N, w0Mod)
	w0Neg.Mod(w0Neg, p256N)

	w0NegM, _ := nistec.NewP256Point().ScalarMult(M, bigIntTo32Bytes(w0Neg))
	temp := nistec.NewP256Point().Add(pA, w0NegM)
	Z, _ := nistec.NewP256Point().ScalarMult(temp, y)

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

	pake2Msg := pake2{PB: c.pB, CB: cB}

	return pake2Msg.Encode().Bytes(), nil
}

func (c *PASEContext) ParsePake3(payload []byte) ([]byte, error) {
	var msg pake3
	if err := msg.Decode(payload); err != nil {
		return nil, err
	}

	if !hmac.Equal(msg.CA, c.cA) {
		return nil, fmt.Errorf("invalid cA confirmation")
	}

	sr := StatusReport{
		GeneralCode:  GeneralCodeSuccess,
		ProtocolID:   ProtocolIDSecureChannel,
		ProtocolCode: CodeSessionEstablishmentSuccess,
	}
	return sr.Encode(), nil
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
