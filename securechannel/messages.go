package securechannel

import (
	"bytes"
	"fmt"

	"github.com/etnz/matter/tlv"
)

// PBKDFParamRequest
type PBKDFParamRequest struct {
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	PasscodeID         uint16
	HasPBKDFParameters bool
	PBKDFParameters    *PBKDFParameters
}

func (m *PBKDFParamRequest) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.InitiatorRandom,
		tlv.ContextTag(2): uint64(m.InitiatorSessionID),
		tlv.ContextTag(3): uint64(m.PasscodeID),
		tlv.ContextTag(4): m.HasPBKDFParameters,
	}
	if m.PBKDFParameters != nil {
		s[tlv.ContextTag(5)] = m.PBKDFParameters.Encode()
	}
	return s
}

func (m *PBKDFParamRequest) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.InitiatorRandom = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.InitiatorSessionID = uint16(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.PasscodeID = uint16(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.HasPBKDFParameters = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(5)]; ok {
		m.PBKDFParameters = &PBKDFParameters{}
		if err := m.PBKDFParameters.Decode(v); err != nil {
			return err
		}
	}
	return nil
}

// PBKDFParameters
type PBKDFParameters struct {
	Iterations uint32
	Salt       []byte
}

func (m *PBKDFParameters) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): uint64(m.Iterations),
		tlv.ContextTag(2): m.Salt,
	}
}

func (m *PBKDFParameters) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.Iterations = uint32(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.Salt = v.([]byte)
	}
	return nil
}

// PBKDFParamResponse
type PBKDFParamResponse struct {
	InitiatorRandom    []byte
	ResponderRandom    []byte
	ResponderSessionID uint16
	PBKDFParameters    *PBKDFParameters
}

func (m *PBKDFParamResponse) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.InitiatorRandom,
		tlv.ContextTag(2): m.ResponderRandom,
		tlv.ContextTag(3): uint64(m.ResponderSessionID),
	}
	if m.PBKDFParameters != nil {
		s[tlv.ContextTag(4)] = m.PBKDFParameters.Encode()
	}
	return s
}

func (m *PBKDFParamResponse) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.InitiatorRandom = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.ResponderRandom = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.ResponderSessionID = uint16(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.PBKDFParameters = &PBKDFParameters{}
		if err := m.PBKDFParameters.Decode(v); err != nil {
			return err
		}
	}
	return nil
}

// Pake1
type Pake1 struct {
	PA []byte
}

func (m *Pake1) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): m.PA,
	}
}

func (m *Pake1) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.PA = v.([]byte)
	}
	return nil
}

// Pake2
type Pake2 struct {
	PB []byte
	CB []byte
}

func (m *Pake2) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): m.PB,
		tlv.ContextTag(2): m.CB,
	}
}

func (m *Pake2) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.PB = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.CB = v.([]byte)
	}
	return nil
}

// Pake3
type Pake3 struct {
	CA []byte
}

func (m *Pake3) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): m.CA,
	}
}

func (m *Pake3) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.CA = v.([]byte)
	}
	return nil
}

// CASESigma1
type CASESigma1 struct {
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	DestinationID      []byte
	InitiatorEphPubKey []byte
	ResumptionID       []byte
	ResumeMIC          []byte
}

func (m *CASESigma1) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.InitiatorRandom,
		tlv.ContextTag(2): uint64(m.InitiatorSessionID),
		tlv.ContextTag(3): m.DestinationID,
		tlv.ContextTag(4): m.InitiatorEphPubKey,
	}
	if len(m.ResumptionID) > 0 {
		s[tlv.ContextTag(5)] = m.ResumptionID
	}
	if len(m.ResumeMIC) > 0 {
		s[tlv.ContextTag(6)] = m.ResumeMIC
	}
	return s
}

func (m *CASESigma1) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.InitiatorRandom = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.InitiatorSessionID = uint16(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.DestinationID = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.InitiatorEphPubKey = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(5)]; ok {
		m.ResumptionID = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(6)]; ok {
		m.ResumeMIC = v.([]byte)
	}
	return nil
}

// CASESigma2
type CASESigma2 struct {
	ResponderRandom    []byte
	ResponderSessionID uint16
	ResponderEphPubKey []byte
	Encrypted          []byte
}

func (m *CASESigma2) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): m.ResponderRandom,
		tlv.ContextTag(2): uint64(m.ResponderSessionID),
		tlv.ContextTag(3): m.ResponderEphPubKey,
		tlv.ContextTag(4): m.Encrypted,
	}
}

func (m *CASESigma2) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.ResponderRandom = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.ResponderSessionID = uint16(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.ResponderEphPubKey = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.Encrypted = v.([]byte)
	}
	return nil
}

// CASESigma2Signed (TBEData2)
type CASESigma2Signed struct {
	ResponderNOC  []byte
	ResponderICAC []byte
	Signature     []byte
	ResumptionID  []byte
}

func (m *CASESigma2Signed) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.ResponderNOC,
		tlv.ContextTag(3): m.Signature,
	}
	if len(m.ResponderICAC) > 0 {
		s[tlv.ContextTag(2)] = m.ResponderICAC
	}
	if len(m.ResumptionID) > 0 {
		s[tlv.ContextTag(4)] = m.ResumptionID
	}
	return s
}

func (m *CASESigma2Signed) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.ResponderNOC = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.ResponderICAC = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.Signature = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.ResumptionID = v.([]byte)
	}
	return nil
}

// CASESigma3
type CASESigma3 struct {
	Encrypted []byte
}

func (m *CASESigma3) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(1): m.Encrypted,
	}
}

func (m *CASESigma3) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.Encrypted = v.([]byte)
	}
	return nil
}

// CASESigma3Signed (TBEData3)
type CASESigma3Signed struct {
	InitiatorNOC  []byte
	InitiatorICAC []byte
	Signature     []byte
}

func (m *CASESigma3Signed) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.InitiatorNOC,
		tlv.ContextTag(3): m.Signature,
	}
	if len(m.InitiatorICAC) > 0 {
		s[tlv.ContextTag(2)] = m.InitiatorICAC
	}
	return s
}

func (m *CASESigma3Signed) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.InitiatorNOC = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.InitiatorICAC = v.([]byte)
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.Signature = v.([]byte)
	}
	return nil
}

// CASESigma3TBS (To-Be-Signed)
type CASESigma3TBS struct {
	InitiatorNOC       []byte
	InitiatorICAC      []byte
	InitiatorEphPubKey []byte
	ResponderEphPubKey []byte
}

func (m *CASESigma3TBS) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): m.InitiatorNOC,
		tlv.ContextTag(3): m.InitiatorEphPubKey,
		tlv.ContextTag(4): m.ResponderEphPubKey,
	}
	if len(m.InitiatorICAC) > 0 {
		s[tlv.ContextTag(2)] = m.InitiatorICAC
	}
	return s
}
