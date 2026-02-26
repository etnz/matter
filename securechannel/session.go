package securechannel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// MessageReceptionState tracks received message counters for replay protection.
type MessageReceptionState struct {
	MaxCounter uint32
	Bitmap     uint32
}

// SessionContext holds the state for a secure session.
type SessionContext struct {
	ID             uint16
	RemoteNodeID   uint64
	MessageCounter uint32
	EncryptionKey  []byte
	DecryptionKey  []byte
	CaseCtx        *caseContext
	PeerState      MessageReceptionState
}

// NewServerSessionFromSigma1 creates a new SessionContext for a responder, parses the Sigma1 payload,
// sets the responder session ID, and generates the Sigma2 payload.
func NewServerSessionFromSigma1(fabric *Fabric, sigma1Payload []byte) (*SessionContext, []byte, error) {
	caseCtx := &caseContext{Fabric: fabric}
	if err := caseCtx.parseSigma1(sigma1Payload); err != nil {
		return nil, nil, err
	}
	// initiate a new session for the CASE exchange.
	var newSessionID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &newSessionID)

	caseCtx.ResponderSessionID = newSessionID
	payload, err := caseCtx.generateSigma2()
	if err != nil {
		return nil, nil, err
	}
	return &SessionContext{
		ID:      caseCtx.ResponderSessionID,
		CaseCtx: caseCtx,
	}, payload, nil
}

// NewClientSession initiates the CASE handshake for an initiator.
func NewClientSession(fabric *Fabric) (*SessionContext, []byte, error) {
	caseCtx := &caseContext{Fabric: fabric}
	payload, err := caseCtx.generateSigma1()
	if err != nil {
		return nil, nil, err
	}
	return &SessionContext{CaseCtx: caseCtx}, payload, nil
}

// HandleSigma3 processes the Sigma3 message, updates the session keys, and returns the response payload.
func (s *SessionContext) HandleSigma3(payload []byte) ([]byte, error) {
	if s.CaseCtx == nil {
		return nil, fmt.Errorf("sigma3 received without session context")
	}

	respPayload, err := s.CaseCtx.parseSigma3(payload)
	if err != nil {
		return nil, err
	}

	s.DecryptionKey, s.EncryptionKey = s.CaseCtx.sessionKeys()
	return respPayload, nil
}

// HandleSigma2 processes the Sigma2 message, updates the session keys and ID, and returns the Sigma3 payload.
func (s *SessionContext) HandleSigma2(payload []byte) ([]byte, error) {
	if s.CaseCtx == nil {
		return nil, fmt.Errorf("CASE context not initialized")
	}
	sigma3Payload, peerSessionID, err := s.CaseCtx.parseSigma2(payload)
	if err != nil {
		return nil, err
	}

	s.ID = peerSessionID
	s.EncryptionKey, s.DecryptionKey = s.CaseCtx.sessionKeys()

	return sigma3Payload, nil
}
