package matter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
)

// temporary hack to tune the verbosity level of the the server.
var serverNetworkLevel = slog.LevelDebug

// MessageWriter allows the handler to write a response.
type MessageWriter interface {
	Response(Message)
}

// Handler responds to an incoming Matter request.
type Handler interface {
	Serve(ctx context.Context, msg Message, w MessageWriter)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as Matter handlers.
type HandlerFunc func(ctx context.Context, msg Message, w MessageWriter)

// Serve calls f(ctx).
func (f HandlerFunc) Serve(ctx context.Context, msg Message, w MessageWriter) {
	f(ctx, msg, w)
}

// responseWriter implements MessageWriter and sends the response back to the connection loop.
type responseWriter Message

func (w *responseWriter) Response(msg Message) { *w = responseWriter(msg) }

// Server defines parameters for running a Matter server.
type Server struct {
	network

	// Addr optionally specifies the UDP address for the server to listen on,
	// in the form "host:port". If empty, ":5540" (standard Matter port) is used.
	Addr     string
	Passcode uint32

	// Handler to invoke, ServeMux is used if nil.
	Handler Handler

	// Interaction Model Handlers
	ReadHandler         func(context.Context, ReadRequestMessage) (ReportDataMessage, error)
	WriteHandler        func(context.Context, WriteRequestMessage) (WriteResponseMessage, error)
	InvokeHandler       func(context.Context, InvokeRequestMessage) (InvokeResponseMessage, error)
	SubscribeHandler    func(context.Context, SubscribeRequestMessage) (SubscribeResponseMessage, error)
	TimedRequestHandler func(context.Context, TimedRequestMessage) (StatusResponseMessage, error)
	ReportDataHandler   func(context.Context, ReportDataMessage) (StatusResponseMessage, error)

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server.
	BaseContext func(net.Addr) context.Context
	Fabric      *Fabric

	// shutdown chan struct{}
	initOnce     sync.Once
	sessions     sync.Map
	paseSessions sync.Map
}

// ListenAndServe listens on the UDP network address s.Addr and then calls Serve.
func (s *Server) ListenAndServe() error {
	s.init()
	addr := s.Addr
	if addr == "" {
		addr = ":5540"
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return s.Serve(conn)
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.network.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: serverNetworkLevel,
		})).With("agent", "server")
	})
}

// Serve accepts incoming packets on the PacketConn and creates a new service goroutine for each.
func (s *Server) Serve(pc net.PacketConn) (err error) {
	// Ensure that everything is ready.
	s.init()

	conn := s.network.new(pc)
	defer conn.close()

	for msg := range conn.inbound {
		// Build a Response to this Request, using the Handler.
		go s.handle(msg, conn.outbound)

	}
	return nil
}

func (s *Server) handle(msg packet, outbound chan<- packet) {
	// create a context and a go routine per request to build Response.
	var ctx context.Context
	if s.BaseContext != nil {
		ctx = s.BaseContext(msg.addr)
	} else {
		ctx = context.Background()
	}

	// execute the inbound flow to parse the message and build a MatterMessage.
	if err := s.inboundFlow(ctx, &msg); err != nil {
		s.network.logger.Warn("failed to process inbound message", "error", err)
		return
	}

	// Delegate to the Handler to build an Application Response.
	var response Message

	var handled bool
	if msg.protocolHeader.ProtocolId == ProtocolIDSecureChannel {
		switch msg.protocolHeader.Opcode {
		case OpCodeCASESigma1:
			var err error
			response, err = s.handleSigma1(&msg)
			if err != nil {
				s.network.logger.Warn("failed to handle Sigma1", "error", err)
				return
			}
			handled = true
		case OpCodeCASESigma3:
			var err error
			response, err = s.handleSigma3(&msg)
			if err != nil {
				s.network.logger.Warn("failed to handle Sigma3", "error", err)
				return
			}
			handled = true
		case OpCodePBKDFParamRequest:
			var err error
			response, err = s.handlePBKDFParamRequest(&msg)
			if err != nil {
				s.network.logger.Warn("failed to handle PBKDFParamRequest", "error", err)
				return
			}
			handled = true
		case OpCodePASEPake1:
			var err error
			response, err = s.handlePake1(&msg)
			if err != nil {
				s.network.logger.Warn("failed to handle Pake1", "error", err)
				return
			}
			handled = true
		case OpCodePASEPake3:
			var err error
			response, err = s.handlePake3(&msg)
			if err != nil {
				s.network.logger.Warn("failed to handle Pake3", "error", err)
				return
			}
			handled = true
		}
	}
	if !handled {
		if msg.protocolHeader.ProtocolId == ProtocolIDInteractionModel {
			switch msg.protocolHeader.Opcode {
			case OpCodeReadRequest:
				if s.ReadHandler != nil {
					var req ReadRequestMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.ReadHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeReportData,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			case OpCodeWriteRequest:
				if s.WriteHandler != nil {
					var req WriteRequestMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.WriteHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeWriteResponse,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			case OpCodeInvokeRequest:
				if s.InvokeHandler != nil {
					var req InvokeRequestMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.InvokeHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeInvokeResponse,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			case OpCodeSubscribeRequest:
				if s.SubscribeHandler != nil {
					var req SubscribeRequestMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.SubscribeHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeSubscribeResponse,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			case OpCodeTimedRequest:
				if s.TimedRequestHandler != nil {
					var req TimedRequestMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.TimedRequestHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeStatusResponse,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			case OpCodeReportData:
				if s.ReportDataHandler != nil {
					var req ReportDataMessage
					if err := req.Decode(msg.payload); err != nil {
						s.network.logger.Error("decode failed", "error", err)
						return
					}
					resp, err := s.ReportDataHandler(ctx, req)
					if err != nil {
						s.network.logger.Error("handler failed", "error", err)
						return
					}
					response = Message{
						ProtocolID: ProtocolIDInteractionModel,
						OpCode:     OpCodeStatusResponse,
						Payload:    resp.Encode(),
					}
					handled = true
				}
			}
		}
		if !handled && s.Handler != nil {
			s.Handler.Serve(ctx, Message{
				ProtocolID: msg.protocolHeader.ProtocolId,
				OpCode:     msg.protocolHeader.Opcode,
				Payload:    msg.payload,
			}, (*responseWriter)(&response))
		}
	}

	// response now contains that response, run the outbound flow to serialize and send the response back to the client.
	s.outboundFlow(ctx, msg, response, outbound)
}

func (s *Server) outboundFlow(ctx context.Context, req packet, resp Message, outbound chan<- packet) {
	// 3. Flow 3: Server Outbound (Sending a Response)
	// This flow describes the server application reacting to the received request, generating a response, and preparing it for the network.

	// Transformation - NewResponse
	// The server application handler generates a response message (or Status Report).
	// It utilizes the exact Exchange ID from the incoming request.
	// Because the server is the Responder, the Initiator (`I`) flag is set to 0.
	outPkt := req.NewResponse(resp)

	// 3. Bootstrapping Server Outbound (Responding with Sigma2)
	if req.header.SessionID == 0 {
		// Transformation (NewSigma2)
		// The server generates a Sigma2 message.
		// (Note: NewResponse above created the packet structure, but payload generation for Sigma2 would happen in the handler.
		// Here we handle the transport transitions).

		// Transition: The server allocates a Local Session Identifier for the future secure session,
		// assigns an unencrypted message counter, and sends Sigma2 back to the client.
		sessionCtx := &sessionContext{ID: 0}
		if err := outPkt.AssignMessageCounter(sessionCtx); err != nil {
			s.network.logger.Error("failed to assign message counter", "error", err)
			return
		}

		// Send the response back to the network layer (Bypass Encryption)
		select {
		case outbound <- outPkt:
		case <-ctx.Done():
		}
		return
	}

	// Transition - PiggybackAck
	// Before the message is finalized, the server checks its Acknowledgement Table.
	// Finding the pending acknowledgement for the client's request, it sets the `A` (Acknowledgement) flag to 1
	// and injects the client's `Acknowledged Message Counter` into the outbound Protocol Header.
	if (req.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
		outPkt.PiggybackAck(req.header.MessageCounter)
	}

	// Transition - AssignMessageCounter
	// The server retrieves and increments its own Local Message Counter for the outgoing session.
	if err := outPkt.AssignMessageCounter(outPkt.session); err != nil {
		s.network.logger.Error("failed to assign message counter", "error", err)
		return
	}

	// Transition - EncryptAndAuthenticate
	// The payload and protocol header are encrypted using AES-CCM with the session's Encryption Key.
	if err := outPkt.EncryptAndAuthenticate(outPkt.session.EncryptionKey); err != nil {
		s.network.logger.Error("failed to encrypt", "error", err)
		return
	}

	// Send the response back to the network layer
	select {
	case outbound <- outPkt:
	case <-ctx.Done():
	}
}

func (s *Server) inboundFlow(ctx context.Context, req *packet) error {
	// 2. Flow 2: Server Inbound (Receiving a Request)
	// This flow describes a server receiving the physical datagram from the network and processing it up the stack.

	// Transition - DecodeMessageHeader
	// The unencrypted Message Header is parsed to extract the Session ID, Message Flags, and Security Flags.
	if err := req.DecodeMessageHeader(req.payload); err != nil {
		s.network.logger.Warn("failed to decode message header", "error", err)
		return err
	}

	// Resolve Session
	if req.header.SessionID == 0 {
		req.session = &sessionContext{ID: 0}
	} else {
		if val, ok := s.sessions.Load(req.header.SessionID); ok {
			req.session = val.(*sessionContext)
		} else {
			return fmt.Errorf("unknown session %d", req.header.SessionID)
		}
	}

	// 2. Bootstrapping Server Inbound (Receiving Sigma1)
	if req.header.SessionID == 0 {
		// Transition (ProcessMessageCounter)
		// The server checks the unencrypted message counter against its Unsecured Session Context.
		if err := req.ProcessMessageCounter(&messageReceptionState{}); err != nil {
			s.network.logger.Warn("replay detected or invalid counter", "error", err)
			return err
		}

		// Transformation (CreateExchange & Route)
		// Because the message has the PROTOCOL_ID_SECURE_CHANNEL Protocol ID and Sigma1 Opcode,
		// the Exchange Layer routes it directly to the Secure Channel protocol handlers.
		if err := req.DecodeProtocolHeader(); err != nil {
			s.network.logger.Warn("failed to decode protocol header", "error", err)
			return err
		}
		return nil
	}

	// Transition - DecryptAndAuthenticate
	// The server applies AES-CCM using the session's Encryption Key.
	var protocolHeaderDecoded bool
	if len(req.session.DecryptionKey) > 0 {
		if err := req.DecryptAndAuthenticate(req.session.DecryptionKey); err != nil {
			s.network.logger.Warn("failed to decrypt and authenticate", "error", err)
			return err
		}
		protocolHeaderDecoded = true
	}

	// Transition - ProcessMessageCounter
	// The decrypted Message Counter is validated against the sender's `MessageReceptionState` sliding window.
	if err := req.ProcessMessageCounter(&messageReceptionState{}); err != nil {
		s.network.logger.Warn("replay detected or invalid counter", "error", err)
		return err
	}

	// Transition - DecodeProtocolHeader
	// The stack inspects the Protocol Header.
	if !protocolHeaderDecoded {
		if err := req.DecodeProtocolHeader(); err != nil {
			s.network.logger.Warn("failed to decode protocol header", "error", err)
			return err
		}
	}
	return nil
}

func (s *Server) handleSigma1(req *packet) (Message, error) {
	caseCtx := &CASEContext{Fabric: s.Fabric}
	if err := caseCtx.ParseSigma1(req.payload); err != nil {
		return Message{}, err
	}

	// TODO: move this new session ID logic to a more central place (there is probably other places where we need to generate a new session ID)
	var newSessionID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &newSessionID)
	caseCtx.ResponderSessionID = newSessionID

	pkt, err := caseCtx.GenerateSigma2()
	if err != nil {
		return Message{}, err
	}

	session := &sessionContext{ID: newSessionID, caseCtx: caseCtx}
	s.sessions.Store(newSessionID, session)

	return Message{
		ProtocolID: pkt.protocolHeader.ProtocolId,
		OpCode:     pkt.protocolHeader.Opcode,
		Payload:    pkt.payload,
	}, nil
}

func (s *Server) handleSigma3(req *packet) (Message, error) {
	val, ok := s.sessions.Load(req.header.SessionID)
	if !ok {
		return Message{}, fmt.Errorf("session not found")
	}
	session := val.(*sessionContext)

	if session.caseCtx == nil {
		return Message{}, fmt.Errorf("session not found")
	}

	if err := session.caseCtx.ParseSigma3(req.payload); err != nil {
		return Message{}, err
	}

	enc, dec := session.caseCtx.SessionKeys()
	session.DecryptionKey = enc
	session.EncryptionKey = dec

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // GeneralCode Success
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // ProtocolId
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // ProtocolCode

	return Message{ProtocolID: ProtocolIDSecureChannel, OpCode: OpCodeStatusReport, Payload: buf.Bytes()}, nil
}

func (s *Server) handlePBKDFParamRequest(req *packet) (Message, error) {
	paseCtx := &PASEContext{Passcode: s.Passcode}
	if paseCtx.Passcode == 0 {
		paseCtx.Passcode = 20202021 // Default passcode
	}
	if err := paseCtx.ParsePBKDFParamRequest(req.payload); err != nil {
		return Message{}, err
	}

	var newSessionID uint16
	binary.Read(rand.Reader, binary.LittleEndian, &newSessionID)
	paseCtx.ResponderSessionID = newSessionID

	pkt, err := paseCtx.GeneratePBKDFParamResponse()
	if err != nil {
		return Message{}, err
	}

	s.paseSessions.Store(req.protocolHeader.ExchangeID, paseCtx)

	return Message{
		ProtocolID: ProtocolIDSecureChannel,
		OpCode:     OpCodePBKDFParamResponse,
		Payload:    pkt.payload,
	}, nil
}

func (s *Server) handlePake1(req *packet) (Message, error) {
	val, ok := s.paseSessions.Load(req.protocolHeader.ExchangeID)
	if !ok {
		return Message{}, fmt.Errorf("PASE context not found")
	}
	paseCtx := val.(*PASEContext)

	pkt, err := paseCtx.ParsePake1AndGeneratePake2(req.payload)
	if err != nil {
		return Message{}, err
	}

	return Message{
		ProtocolID: ProtocolIDSecureChannel,
		OpCode:     OpCodePASEPake2,
		Payload:    pkt.payload,
	}, nil
}

func (s *Server) handlePake3(req *packet) (Message, error) {
	val, ok := s.paseSessions.Load(req.protocolHeader.ExchangeID)
	if !ok {
		return Message{}, fmt.Errorf("PASE context not found")
	}
	paseCtx := val.(*PASEContext)

	if err := paseCtx.ParsePake3(req.payload); err != nil {
		return Message{}, err
	}

	enc, dec, _ := paseCtx.SessionKeys()
	session := &sessionContext{
		ID:            paseCtx.ResponderSessionID,
		DecryptionKey: enc,
		EncryptionKey: dec,
	}
	s.sessions.Store(paseCtx.ResponderSessionID, session)
	s.paseSessions.Delete(req.protocolHeader.ExchangeID)

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // GeneralCode Success
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // ProtocolId
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // ProtocolCode

	return Message{ProtocolID: ProtocolIDSecureChannel, OpCode: OpCodeStatusReport, Payload: buf.Bytes()}, nil
}
