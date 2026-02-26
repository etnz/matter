package securechannel

import "fmt"

// SessionContext holds the state for a secure session.
type SessionContext struct {
	ID             uint16
	RemoteNodeID   uint64
	MessageCounter uint32
	EncryptionKey  []byte
	DecryptionKey  []byte
	CaseCtx        *CASEContext
}

// HandleSigma3 processes the Sigma3 message, updates the session keys, and returns the response payload.
func (s *SessionContext) HandleSigma3(payload []byte) ([]byte, error) {
	if s.CaseCtx == nil {
		return nil, fmt.Errorf("sigma3 received without session context")
	}

	respPayload, err := s.CaseCtx.ParseSigma3(payload)
	if err != nil {
		return nil, err
	}

	s.DecryptionKey, s.EncryptionKey = s.CaseCtx.SessionKeys()
	return respPayload, nil
}
