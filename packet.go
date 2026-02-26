package matter

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/etnz/matter/securechannel"
	"github.com/tom-code/gomat/ccm"
)

// TODO: use a standard ccm implementation after https://github.com/golang/go/issues/27484

// transportType is a placeholder for the transport type.
type transportType int

// packet holds the context required to perform a matter message.
type packet struct {
	addr    net.Addr // Source or destination address, depending on the direction of the message.
	payload []byte   // The message payload as read from the network or to be written to the network.
	//resp           chan<- Packet         // Communication to respond to this message, if applicable.
	header         messageHeader                 // Unencrypted message header
	protocolHeader protocolMessageHeader         // Encrypted/Decrypted protocol header
	session        *securechannel.SessionContext // The session associated with this packet
	isEncrypted    bool                          // Whether the payload is already encrypted
}

func (p packet) String() string {
	return fmt.Sprintf("{Addr: %v, SessID: %d, MsgCtr: %d, Proto: %s, Op: %s, ExchID: %d, Len: %d}",
		p.addr,
		p.header.SessionID,
		p.header.MessageCounter,
		p.protocolHeader.ProtocolId,
		p.protocolHeader.Opcode.String(p.protocolHeader.ProtocolId),
		p.protocolHeader.ExchangeID,
		len(p.payload),
	)
}

// WriteTo writes the packet to the network connection, encoding headers as necessary.
func (p *packet) WriteTo(pc net.PacketConn) (int, error) {
	var buf bytes.Buffer
	p.header.Encode(&buf)
	if !p.isEncrypted {
		p.protocolHeader.Encode(&buf)
	}
	buf.Write(p.payload)
	return pc.WriteTo(buf.Bytes(), p.addr)
}

// 1. Originating Transformations (Client/Initiator Genesis)
// These transformations represent the birth of a new `Message` object on the initiator side,
// allocating memory, assigning an Exchange ID, and setting up the initial application or handshake payload.

// NewRequest creates a brand new message to initiate a transaction (e.g., a Read, Write, or Invoke request) from the client.
// The node in the Initiator role must allocate a new Exchange ID and always set the Initiator (`I`) flag in the Exchange Flags.
// The message is bound to an established secure session.
func NewRequest(sessionCtx *securechannel.SessionContext, protocolID ProtocolID, opCode OpCode, payload []byte) *packet {
	var exchangeID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &exchangeID)
	pkt := &packet{
		header: messageHeader{
			SessionID: 0,
		},
		protocolHeader: protocolMessageHeader{
			ProtocolId:    protocolID,
			Opcode:        opCode,
			ExchangeID:    exchangeID,
			ExchangeFlags: FlagInitiator,
		},
		payload: payload,
		session: sessionCtx,
	}
	if sessionCtx != nil {
		pkt.header.SessionID = sessionCtx.ID
	}
	return pkt
}

// 2. Inbound Transitions (Datagram → App Payload)
// These transitions mutate an incoming byte slice or `Message` struct in-place as it is parsed from the network and ascends the secure channel stack.

// DecodeMessageHeader parses the unencrypted Message Header fields to determine the Session ID, Message Flags, Security Flags,
// Message Counter, and Source/Destination Node IDs. This allows the stack to locate the correct Session Context and cryptographic keys needed for the next steps.
func (p *packet) DecodeMessageHeader(datagram []byte) error {
	var err error
	p.header, p.payload, err = decodeMessageHeader(datagram)
	return err
}

// RemovePrivacyObfuscation uses the AES-CTR decryption function with the derived `privacyKey` and a Privacy Nonce
// to deobfuscate the Message Counter and Node IDs *before* the message can be authenticated.
// This is done if the Privacy (`P`) flag is set in the incoming message's Security Flags.
func (p *packet) RemovePrivacyObfuscation(privacyKey []byte) error {
	return nil
}

// DecryptAndAuthenticate uses AES-CCM to perform AEAD decryption and validate the Message Integrity Check (MIC) over the message payload and header.
// If the tag verification fails, the contents are discarded and processing stops.
func (p *packet) DecryptAndAuthenticate(decryptionKey []byte) error {
	var aad bytes.Buffer
	p.header.Encode(&aad)

	nonce := make([]byte, 13)
	nonce[0] = p.header.SecurityFlags
	binary.LittleEndian.PutUint32(nonce[1:5], p.header.MessageCounter)
	if len(p.header.SourceNodeID) == 8 {
		copy(nonce[5:], p.header.SourceNodeID)
	}

	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return err
	}
	aesccm, err := ccm.NewCCM(block, 16, 13)
	if err != nil {
		return err
	}

	plaintext, err := aesccm.Open(nil, nonce, p.payload, aad.Bytes())
	if err != nil {
		return err
	}

	p.protocolHeader, p.payload, err = decodeProtocolMessageHeader(plaintext)
	return err
}

// ProcessMessageCounter prevents replay attacks and duplicate processing.
// It validates the decrypted Message Counter against a sliding reception window.
// If the counter is outside the valid window or has been seen before, the message is marked as a duplicate
// and might only be used to trigger an acknowledgment (if the `R` flag is set) before being dropped.
func (p *packet) ProcessMessageCounter() error {
	if p.header.SessionID == 0 {
		if p.session == nil {
			p.session = &securechannel.SessionContext{}
		}
	}
	peerState := &p.session.PeerState

	counter := p.header.MessageCounter
	if counter > peerState.MaxCounter {
		shift := counter - peerState.MaxCounter
		if shift >= 32 {
			peerState.Bitmap = 0
		} else {
			peerState.Bitmap <<= shift
		}
		peerState.MaxCounter = counter
		peerState.Bitmap |= 1
		return nil
	}
	offset := peerState.MaxCounter - counter
	if offset >= 32 {
		return fmt.Errorf("message counter too old")
	}
	mask := uint32(1) << offset
	if (peerState.Bitmap & mask) != 0 {
		return fmt.Errorf("duplicate message counter")
	}
	peerState.Bitmap |= mask
	return nil
}

// DecodeProtocolHeader parses the plaintext payload to extract the Protocol Header (Exchange Flags, Protocol Opcode, Exchange ID, Protocol ID,
// and Acknowledged Message Counter) so the message can be correctly routed to the proper Exchange Context.
func (p *packet) DecodeProtocolHeader() error {
	var err error
	p.protocolHeader, p.payload, err = decodeProtocolMessageHeader(p.payload)
	return err
}

// 3. Reactive Transformations (Server/Responder Handlers)
// These methods create a new outbound `Message` as a direct reaction to a successfully decoded and verified inbound message.

// NewStandaloneAck drives the Message Reliability Protocol (MRP).
// If an incoming message requests an acknowledgment (Reliability `R` flag = 1) but the application has no immediate response to send,
// this generates a new, empty message. The `A` flag is set to 1, and the `Acknowledged Message Counter` field is populated with the incoming message's counter.
func (p *packet) NewStandaloneAck() packet {
	return packet{
		addr: p.addr,
		header: messageHeader{
			SessionID:         p.header.SessionID,
			SourceNodeID:      p.header.DestinationNodeID,
			DestinationNodeID: p.header.SourceNodeID,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeFlags: FlagAck,
			Opcode:        OpCodeMRPStandaloneAck,
			ProtocolId:    ProtocolIDSecureChannel,
			ExchangeID:    p.protocolHeader.ExchangeID,
			AckCounter:    p.header.MessageCounter,
		},
		session: p.session,
	}
}

// NewResponse creates an application-layer response within an existing Exchange.
// It copies the `Exchange ID` from the incoming request. Because it is a response, the `I` (Initiator) flag must be flipped relative to the request,
// and the specific Protocol ID and OpCode are applied.
func (m *packet) NewResponse(msg Message) packet {
	p := packet{
		addr:    m.addr,
		payload: msg.Payload,
		session: m.session,
	}

	p.protocolHeader = protocolMessageHeader{
		ProtocolId: msg.ProtocolID,
		Opcode:     msg.OpCode,
		ExchangeID: m.protocolHeader.ExchangeID,
	}

	// Flip the Initiator flag relative to the request
	if (m.protocolHeader.ExchangeFlags & FlagInitiator) == 0 {
		p.protocolHeader.ExchangeFlags |= FlagInitiator
	}

	if p.session != nil {
		p.header.SessionID = p.session.ID
	}

	return p
}

// NewStatusReport transforms the request into a Status Report message if a server encounters an error
// (e.g., cannot process the action, unsupported endpoint, etc.).
func (p *packet) NewStatusReport(statusCode uint8, protocolID ProtocolID) packet {
	return packet{}
}

// NewChunkedResponse breaks a generated response (like a large `ReportData` payload) into a series of smaller messages if it exceeds the IPv6 MTU limits.
// The `MoreChunkedMessages` flag must be set to true on all messages except the final one, to instruct the receiver to await further chunks.
func (p *packet) NewChunkedResponse(payloadChunks [][]byte) []packet {
	return []packet{}
}

// 4. Outbound Transitions (App Payload → Datagram)
// These transitions mutate an outbound `Message` in-place, preparing it to be transmitted onto the physical network layer.

// PiggybackAck is an optimization for the Message Reliability Protocol.
// If the server is preparing an outbound message and there is a pending acknowledgment for the same Exchange context,
// this transition injects the `A` flag and the `Acknowledged Message Counter` into the outbound message's header, canceling the need for a separate standalone ack.
func (p *packet) PiggybackAck(pendingAckMsgCounter uint32) error {
	p.protocolHeader.ExchangeFlags |= FlagAck
	p.protocolHeader.AckCounter = pendingAckMsgCounter
	return nil
}

// AssignMessageCounter allocates a monotonically increasing 32-bit counter from the Local Message Counter state within the Secure Session context.
// The counter is injected into the header and acts as the nonce for AES-CCM encryption.
func (p *packet) AssignMessageCounter(sessionCtx *securechannel.SessionContext) error {
	sessionCtx.MessageCounter++
	p.header.MessageCounter = sessionCtx.MessageCounter
	return nil
}

// EncryptAndAuthenticate uses AES-CCM to encrypt the application payload and the Protocol Header.
// The unencrypted Message Header is passed as Associated Data (A). The result is the ciphertext and a Message Integrity Check (MIC) tag appended to the frame.
func (p *packet) EncryptAndAuthenticate(encryptionKey []byte) error {
	var aad bytes.Buffer
	p.header.Encode(&aad)

	nonce := make([]byte, 13)
	nonce[0] = p.header.SecurityFlags
	binary.LittleEndian.PutUint32(nonce[1:5], p.header.MessageCounter)
	if len(p.header.SourceNodeID) == 8 {
		copy(nonce[5:], p.header.SourceNodeID)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}
	aesccm, err := ccm.NewCCM(block, 16, 13)
	if err != nil {
		return err
	}

	var plaintext bytes.Buffer
	p.protocolHeader.Encode(&plaintext)
	plaintext.Write(p.payload)

	p.payload = aesccm.Seal(nil, nonce, plaintext.Bytes(), aad.Bytes())
	p.isEncrypted = true
	return nil
}

// ApplyPrivacyObfuscation uses AES-CTR to encrypt the Message Counter and the Source/Destination Node IDs in the header
// if the message requires metadata protection (the `P` flag is set).
// It uses the AES-CCM MIC generated in the previous step as the AES-CTR nonce.
func (p *packet) ApplyPrivacyObfuscation(privacyKey []byte) error {
	return nil
}

// EncodeFraming performs a final formatting step dependent on the network transport.
// If the message is being dispatched over TCP, it requires prepending a length field to accommodate stream-based segmentation and reassembly.
// UDP messages skip this step.
func (p *packet) EncodeFraming(transportType transportType) error {
	return nil
}
