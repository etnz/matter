package securechannel

import (
	"bytes"
	"encoding/binary"
)

type GeneralCode uint16

const (
	GeneralCodeSuccess           GeneralCode = 0
	GeneralCodeFailure           GeneralCode = 1
	GeneralCodeBadPrecondition   GeneralCode = 2
	GeneralCodeOutOfRange        GeneralCode = 3
	GeneralCodeBadRequest        GeneralCode = 4
	GeneralCodeUnsupported       GeneralCode = 5
	GeneralCodeUnexpected        GeneralCode = 6
	GeneralCodeResourceExhausted GeneralCode = 7
	GeneralCodeBusy              GeneralCode = 8
	GeneralCodeTimeout           GeneralCode = 9
	GeneralCodeContinue          GeneralCode = 10
	GeneralCodeAborted           GeneralCode = 11
	GeneralCodeInvalidArgument   GeneralCode = 12
	GeneralCodeNotFound          GeneralCode = 13
	GeneralCodeAlreadyExists     GeneralCode = 14
	GeneralCodePermissionDenied  GeneralCode = 15
	GeneralCodeDataLoss          GeneralCode = 16
)

type ProtocolCode uint16

const (
	CodeSessionEstablishmentSuccess ProtocolCode = 0x0000
	CodeNoSharedTrustRoots          ProtocolCode = 0x0001
	CodeInvalidParameter            ProtocolCode = 0x0002
	CodeCloseSession                ProtocolCode = 0x0003
	CodeBusy                        ProtocolCode = 0x0004
)

const ProtocolIDSecureChannel = 0x0000

type StatusReport struct {
	GeneralCode  GeneralCode
	ProtocolID   uint32
	ProtocolCode ProtocolCode
	ProtocolData []byte
}

func (s *StatusReport) Encode() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, s.GeneralCode)
	binary.Write(buf, binary.LittleEndian, s.ProtocolID)
	binary.Write(buf, binary.LittleEndian, s.ProtocolCode)
	if len(s.ProtocolData) > 0 {
		buf.Write(s.ProtocolData)
	}
	return buf.Bytes()
}

func (s *StatusReport) Decode(data []byte) error {
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &s.GeneralCode); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &s.ProtocolID); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &s.ProtocolCode); err != nil {
		return err
	}
	if buf.Len() > 0 {
		s.ProtocolData = make([]byte, buf.Len())
		buf.Read(s.ProtocolData)
	}
	return nil
}
