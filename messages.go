package matter

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Message represents a Matter application level message.
type Message struct {
	ProtocolID ProtocolID
	OpCode     OpCode
	Payload    []byte
}

type ProtocolID uint16

const (
	ProtocolIDSecureChannel             ProtocolID = 0 // Section 4.10.1, “Secure Channel Protocol Messages”
	ProtocolIDInteractionModel          ProtocolID = 1 //Section 10.2.1, “IM Protocol Messages”
	ProtocolIDBDX                       ProtocolID = 2 // Section 11.21.3.1, “BDX Protocol Messages”
	ProtocolIDUserDirectedCommissioning ProtocolID = 3 //  Section 5.3.2, “UDC Protocol Messages”
	ProtocolIDForTesting                ProtocolID = 4 // Reserved for bespoke protocols run in an isolated test
// 0x0005 -0xFFFF Reserved
)

func (p ProtocolID) String() string {
	switch p {
	case ProtocolIDSecureChannel:
		return "SecureChannel"
	case ProtocolIDInteractionModel:
		return "InteractionModel"
	case ProtocolIDBDX:
		return "BDX"
	case ProtocolIDUserDirectedCommissioning:
		return "UserDirectedCommissioning"
	case ProtocolIDForTesting:
		return "ForTesting"
	default:
		return "Unknown"
	}
}

type OpCode byte

const (
	// Protocol Secure Channel Op Codes
	OpCodeMsgCounterSyncReq  OpCode = 0x00 // The Message Counter Synchronization Request message queries the current message counter from a peer to bootstrap replay protection.
	OpCodeMsgCounterSyncRsp  OpCode = 0x01 // The Message Counter Synchronization Response message provides the current message counter from a peer to bootstrap replay protection.
	OpCodeMRPStandaloneAck   OpCode = 0x10 // This message is dedicated for the purpose of sending a stand-alone acknowledgement when there is no other data message available to piggyback an acknowledgement on top of.
	OpCodePBKDFParamRequest  OpCode = 0x20 // The request for PBKDF parameters necessary to complete the PASE protocol.
	OpCodePBKDFParamResponse OpCode = 0x21 // The PBKDF parameters sent in response to PBKDFParamRequest during the PASE protocol.
	OpCodePASEPake1          OpCode = 0x22 // The first PAKE message of the PASE protocol.
	OpCodePASEPake2          OpCode = 0x23 // The second PAKE message of the PASE protocol.
	OpCodePASEPake3          OpCode = 0x24 // The third PAKE message of the PASE protocol.
	OpCodeCASESigma1         OpCode = 0x30 // The first message of the CASE protocol.
	OpCodeCASESigma2         OpCode = 0x31 // The second message of the CASE protocol.
	OpCodeCASESigma3         OpCode = 0x32 // The third message of the CASE protocol.
	OpCodeCASESigma2Resume   OpCode = 0x33 // The second resumption message of the CASE protocol.
	OpCodeStatusReport       OpCode = 0x40 // The Status Report message encodes the result of an operation in the Secure Channel as well as other protocols.
	OpCodeICDCheckIn         OpCode = 0x50 // The Check-in message notifies a client that the ICD is available for communication.

	// Protocol Interaction Model Op Codes
	OpCodeStatusResponse    OpCode = 0x01 // StatusResponseMessage
	OpCodeReadRequest       OpCode = 0x02 // ReadRequestMessage
	OpCodeSubscribeRequest  OpCode = 0x03 // SubscribeRequestMessage
	OpCodeSubscribeResponse OpCode = 0x04 // SubscribeResponseMessage
	OpCodeReportData        OpCode = 0x05 // ReportDataMessage
	OpCodeWriteRequest      OpCode = 0x06 // WriteRequestMessage
	OpCodeWriteResponse     OpCode = 0x07 // WriteResponseMessage
	OpCodeInvokeRequest     OpCode = 0x08 // InvokeRequestMessage
	OpCodeInvokeResponse    OpCode = 0x09 // InvokeResponseMessage
	OpCodeTimedRequest      OpCode = 0x0A // TimedRequestMessage

	// BDX Protocol Opcodes
	OpCodeBDXSendInit           OpCode = 0x01 // SendInit
	OpCodeBDXSendAccept         OpCode = 0x02 // SendAccept
	OpCodeBDXReceiveInit        OpCode = 0x04 // ReceiveInit
	OpCodeBDXReceiveAccept      OpCode = 0x05 // ReceiveAccept
	OpCodeBDXBlockQuery         OpCode = 0x10 // BlockQuery
	OpCodeBDXBlock              OpCode = 0x11 // Block
	OpCodeBDXBlockEOF           OpCode = 0x12 // BlockEOF
	OpCodeBDXBlockAck           OpCode = 0x13 // BlockAck
	OpCodeBDXBlockAckEOF        OpCode = 0x14 // BlockAckEOF
	OpCodeBDXBlockQueryWithSkip OpCode = 0x15 // BlockQueryWithSkip

	// Protocol User Directed Commissioning Op Codes
	OpCodeUDCIdentificationDeclaration OpCode = 0x00 // IdentificationDeclaration
	OpCodeUDCCommissionerDeclaration   OpCode = 0x01 // CommissionerDeclaration

)

func (o OpCode) String(pid ProtocolID) string {
	switch pid {
	case ProtocolIDSecureChannel:
		switch o {
		case OpCodeMsgCounterSyncReq:
			return "MsgCounterSyncReq"
		case OpCodeMsgCounterSyncRsp:
			return "MsgCounterSyncRsp"
		case OpCodeMRPStandaloneAck:
			return "MRPStandaloneAck"
		case OpCodePBKDFParamRequest:
			return "PBKDFParamRequest"
		case OpCodePBKDFParamResponse:
			return "PBKDFParamResponse"
		case OpCodePASEPake1:
			return "PASEPake1"
		case OpCodePASEPake2:
			return "PASEPake2"
		case OpCodePASEPake3:
			return "PASEPake3"
		case OpCodeCASESigma1:
			return "CASESigma1"
		case OpCodeCASESigma2:
			return "CASESigma2"
		case OpCodeCASESigma3:
			return "CASESigma3"
		case OpCodeCASESigma2Resume:
			return "CASESigma2Resume"
		case OpCodeStatusReport:
			return "StatusReport"
		case OpCodeICDCheckIn:
			return "ICDCheckIn"
		}
	case ProtocolIDInteractionModel:
		switch o {
		case OpCodeStatusResponse:
			return "StatusResponse"
		case OpCodeReadRequest:
			return "ReadRequest"
		case OpCodeSubscribeRequest:
			return "SubscribeRequest"
		case OpCodeSubscribeResponse:
			return "SubscribeResponse"
		case OpCodeReportData:
			return "ReportData"
		case OpCodeWriteRequest:
			return "WriteRequest"
		case OpCodeWriteResponse:
			return "WriteResponse"
		case OpCodeInvokeRequest:
			return "InvokeRequest"
		case OpCodeInvokeResponse:
			return "InvokeResponse"
		case OpCodeTimedRequest:
			return "TimedRequest"
		}
	case ProtocolIDBDX:
		switch o {
		case OpCodeBDXSendInit:
			return "SendInit"
		case OpCodeBDXSendAccept:
			return "SendAccept"
		case OpCodeBDXReceiveInit:
			return "ReceiveInit"
		case OpCodeBDXReceiveAccept:
			return "ReceiveAccept"
		case OpCodeBDXBlockQuery:
			return "BlockQuery"
		case OpCodeBDXBlock:
			return "Block"
		case OpCodeBDXBlockEOF:
			return "BlockEOF"
		case OpCodeBDXBlockAck:
			return "BlockAck"
		case OpCodeBDXBlockAckEOF:
			return "BlockAckEOF"
		case OpCodeBDXBlockQueryWithSkip:
			return "BlockQueryWithSkip"
		}
	case ProtocolIDUserDirectedCommissioning:
		switch o {
		case OpCodeUDCIdentificationDeclaration:
			return "IdentificationDeclaration"
		case OpCodeUDCCommissionerDeclaration:
			return "CommissionerDeclaration"
		}
	}
	return "Unknown " + fmt.Sprintf("%x", byte(o))
}

const (
	FlagInitiator = 0x01
	FlagAck       = 0x02
	FlagReliable  = 0x10
	FlagPrivacy   = 0x80
)

type messageHeader struct {
	Flags             uint8
	SessionID         uint16
	SecurityFlags     uint8
	MessageCounter    uint32
	SourceNodeID      []byte
	DestinationNodeID []byte
}

func decodeMessageHeader(msg []byte) (header messageHeader, payload []byte, err error) {
	buf := bytes.NewBuffer(msg)
	if err = header.Decode(buf); err != nil {
		return
	}
	return header, buf.Bytes(), nil
}

func (m *messageHeader) Encode(data *bytes.Buffer) {
	var flags uint8
	if len(m.SourceNodeID) == 8 {
		flags |= 0x04
	}
	if len(m.DestinationNodeID) == 2 {
		flags |= 0x02
	} else if len(m.DestinationNodeID) == 8 {
		flags |= 0x01
	}
	m.Flags = flags

	data.WriteByte(m.Flags)
	binary.Write(data, binary.LittleEndian, m.SessionID)
	data.WriteByte(m.SecurityFlags)
	binary.Write(data, binary.LittleEndian, m.MessageCounter)
	if len(m.SourceNodeID) > 0 {
		data.Write(m.SourceNodeID)
	}
	if len(m.DestinationNodeID) > 0 {
		data.Write(m.DestinationNodeID)
	}
}

func (m *messageHeader) Decode(data *bytes.Buffer) error {
	var err error
	m.Flags, err = data.ReadByte()
	if err != nil {
		return err
	}
	if err := binary.Read(data, binary.LittleEndian, &m.SessionID); err != nil {
		return err
	}
	m.SecurityFlags, err = data.ReadByte()
	if err != nil {
		return err
	}
	if err := binary.Read(data, binary.LittleEndian, &m.MessageCounter); err != nil {
		return err
	}
	if (m.Flags & 0x04) != 0 {
		m.SourceNodeID = make([]byte, 8)
		if _, err := data.Read(m.SourceNodeID); err != nil {
			return err
		}
	}
	dsiz := m.Flags & 0x03
	switch dsiz {
	case 1:
		m.DestinationNodeID = make([]byte, 8)
		if _, err := data.Read(m.DestinationNodeID); err != nil {
			return err
		}
	case 2:
		m.DestinationNodeID = make([]byte, 2)
		if _, err := data.Read(m.DestinationNodeID); err != nil {
			return err
		}
	}
	return nil
}

type protocolMessageHeader struct {
	ExchangeFlags uint8
	Opcode        OpCode
	ExchangeID    uint16
	ProtocolId    ProtocolID
	AckCounter    uint32
}

func decodeProtocolMessageHeader(msg []byte) (proto protocolMessageHeader, payload []byte, err error) {
	buf := bytes.NewBuffer(msg)
	if err = proto.Decode(buf); err != nil {
		return
	}
	return proto, buf.Bytes(), nil
}

func (p *protocolMessageHeader) Encode(data *bytes.Buffer) {
	data.WriteByte(p.ExchangeFlags)
	data.WriteByte(byte(p.Opcode))
	binary.Write(data, binary.LittleEndian, p.ExchangeID)
	binary.Write(data, binary.LittleEndian, p.ProtocolId)
	if (p.ExchangeFlags & 0x02) != 0 {
		binary.Write(data, binary.LittleEndian, p.AckCounter)
	}
}

func (p *protocolMessageHeader) Decode(data *bytes.Buffer) error {
	var err error
	p.ExchangeFlags, err = data.ReadByte()
	if err != nil {
		return err
	}
	opcode, err := data.ReadByte()
	if err != nil {
		return err
	}
	p.Opcode = OpCode(opcode)
	if err := binary.Read(data, binary.LittleEndian, &p.ExchangeID); err != nil {
		return err
	}
	if err := binary.Read(data, binary.LittleEndian, &p.ProtocolId); err != nil {
		return err
	}
	if (p.ExchangeFlags & 0x02) != 0 {
		if err := binary.Read(data, binary.LittleEndian, &p.AckCounter); err != nil {
			return err
		}
	}
	return nil
}
