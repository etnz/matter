package matter

import (
	"log/slog"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/etnz/matter/securechannel"
)

// TODO: unexpose everything in this file
const (
	maxTransmissions     = 5
	standaloneAckTimeout = 200 * time.Millisecond
	backoffBase          = 1.6
	backoffJitterMax     = 0.25
	baseRetryInterval    = 300 * time.Millisecond // Default active interval
)

type retransmissionEntry struct {
	ExchangeID     uint16
	MessageCounter uint32
	Packet         packet
	SendCount      int
	NextTimeout    time.Time
}

type ackEntry struct {
	ExchangeID        uint16
	MessageCounter    uint32
	Timeout           time.Time
	StandaloneAckSent bool
	// Data needed to construct Standalone ACK
	Addr              net.Addr
	Session           *securechannel.SessionContext
	SourceNodeID      []byte
	DestinationNodeID []byte
}

type mrpEngine struct {
	mu           sync.Mutex
	retransTable map[uint32]*retransmissionEntry // Keyed by MessageCounter
	ackTable     map[uint16]*ackEntry            // Keyed by ExchangeID
	outbound     chan<- packet
	logger       *slog.Logger
	closed       chan struct{}
	wake         chan struct{}
}

// newMRPEngine creates a new Message Reliability Protocol engine.
func newMRPEngine(outbound chan<- packet, logger *slog.Logger) *mrpEngine {
	m := &mrpEngine{
		retransTable: make(map[uint32]*retransmissionEntry),
		ackTable:     make(map[uint16]*ackEntry),
		outbound:     outbound,
		logger:       logger,
		closed:       make(chan struct{}),
		wake:         make(chan struct{}, 1),
	}
	go m.run()
	return m
}

// stop shuts down the MRP engine and its background goroutine.
func (m *mrpEngine) stop() {
	close(m.closed)
}

// notify wakes up the run loop to re-evaluate timers immediately.
func (m *mrpEngine) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// run is the main loop that manages timers for retransmissions and acknowledgements.
func (m *mrpEngine) run() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		next := m.tick()
		if next.IsZero() {
			// There is no event in the foreseable future: we sleep until the end or a notify
			// wait on close or wake
			select {
			case <-m.closed:
				return
			case <-m.wake:
			}
		} else {
			sleep := time.Until(next)
			if sleep < 0 {
				// the next has already expired
				continue
			}
			timer.Reset(sleep)
			// We schedule a timer to tick on that next even and wait on all three possible events.
			select {
			case <-m.closed:
				return
			case <-m.wake:
			case <-timer.C:
			}
		}
	}
}

// tick checks the state of the retransmission and acknowledgement tables.
// It sends pending standalone ACKs and retransmits messages if their backoff timer has expired.
// It returns the time of the next scheduled event (timeout), or a zero time if no events are pending.
func (m *mrpEngine) tick() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var nextWakeup time.Time

	// Check ACKs
	for id, entry := range m.ackTable {
		if !entry.StandaloneAckSent && now.After(entry.Timeout) {
			// Send Standalone ACK
			ackPkt := packet{
				addr: entry.Addr,
				header: messageHeader{
					SessionID:         entry.Session.ID,
					SourceNodeID:      entry.DestinationNodeID, // Swap source/dest
					DestinationNodeID: entry.SourceNodeID,
				},
				protocolHeader: protocolMessageHeader{
					ExchangeFlags: FlagAck,
					Opcode:        OpCodeMRPStandaloneAck,
					ProtocolId:    ProtocolIDSecureChannel,
					ExchangeID:    entry.ExchangeID,
					AckCounter:    entry.MessageCounter,
				},
				session: entry.Session,
			}

			if entry.Session != nil && entry.Session.ID != 0 {
				if err := ackPkt.AssignMessageCounter(entry.Session); err == nil {
					if err := ackPkt.EncryptAndAuthenticate(entry.Session.EncryptionKey); err == nil {
						select {
						case m.outbound <- ackPkt:
							entry.StandaloneAckSent = true
							m.logger.Debug("MRP: sent standalone ACK", "exchangeID", id, "ackCounter", entry.MessageCounter)
						default:
						}
					}
				}
			} else if entry.Session != nil {
				// Unsecured session (e.g. PASE/CASE handshake)
				ackPkt.AssignMessageCounter(entry.Session)
				select {
				case m.outbound <- ackPkt:
					entry.StandaloneAckSent = true
					m.logger.Debug("MRP: sent standalone ACK (unsecured)", "exchangeID", id)
				default:
				}
			}

			delete(m.ackTable, id)
		} else if !entry.StandaloneAckSent {
			if nextWakeup.IsZero() || entry.Timeout.Before(nextWakeup) {
				nextWakeup = entry.Timeout
			}
		}
	}

	// Check Retransmissions
	for ctr, entry := range m.retransTable {
		if now.After(entry.NextTimeout) {
			if entry.SendCount >= maxTransmissions {
				m.logger.Warn("MRP: max transmissions reached", "exchangeID", entry.ExchangeID)
				delete(m.retransTable, ctr)
				continue
			}

			entry.SendCount++
			entry.NextTimeout = now.Add(m.calculateBackoff(entry.SendCount))
			m.logger.Debug("MRP: retransmitting", "msgCounter", ctr, "attempt", entry.SendCount)

			select {
			case m.outbound <- entry.Packet:
			default:
			}
		}

		if nextWakeup.IsZero() || entry.NextTimeout.Before(nextWakeup) {
			nextWakeup = entry.NextTimeout
		}
	}
	return nextWakeup
}

// calculateBackoff computes the time to wait before the next retransmission attempt.
func (m *mrpEngine) calculateBackoff(sendCount int) time.Duration {
	// t = I * (F ^ m) + jitter
	mVal := float64(sendCount - 1)
	if mVal < 0 {
		mVal = 0
	}

	base := float64(baseRetryInterval) * math.Pow(backoffBase, mVal)
	jitter := base * rand.Float64() * backoffJitterMax

	return time.Duration(base + jitter)
}

// registerReliableMessage adds an outbound message to the retransmission table.
func (m *mrpEngine) registerReliableMessage(p packet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initial timeout
	timeout := time.Now().Add(m.calculateBackoff(1))

	m.retransTable[p.header.MessageCounter] = &retransmissionEntry{
		ExchangeID:     p.protocolHeader.ExchangeID,
		MessageCounter: p.header.MessageCounter,
		Packet:         p,
		SendCount:      0,
		NextTimeout:    timeout,
	}
	m.notify()
}

// acknowledgeMessage processes an incoming acknowledgement, removing the associated message from the retransmission table.
func (m *mrpEngine) acknowledgeMessage(ackCounter uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.retransTable[ackCounter]; ok {
		delete(m.retransTable, ackCounter)
		m.logger.Debug("MRP: received ACK", "ackCounter", ackCounter)
	}
	m.notify()
}

// scheduleAck records that a reliable message was received and a standalone ACK should be sent if not piggybacked within the timeout.
func (m *mrpEngine) scheduleAck(p *packet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ackTable[p.protocolHeader.ExchangeID] = &ackEntry{
		ExchangeID:        p.protocolHeader.ExchangeID,
		MessageCounter:    p.header.MessageCounter,
		Timeout:           time.Now().Add(standaloneAckTimeout),
		StandaloneAckSent: false,
		Addr:              p.addr,
		Session:           p.session,
		SourceNodeID:      p.header.SourceNodeID,
		DestinationNodeID: p.header.DestinationNodeID,
	}
	m.notify()
}

// piggybackAck checks if there is a pending acknowledgement for the given exchange ID.
// If found, it returns the message counter to acknowledge and removes the pending ACK entry.
func (m *mrpEngine) piggybackAck(exchangeID uint16) (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.ackTable[exchangeID]; ok {
		delete(m.ackTable, exchangeID)
		m.notify()
		return entry.MessageCounter, true
	}
	return 0, false
}

// sendStandaloneAck constructs and sends a standalone acknowledgement packet immediately.
func (m *mrpEngine) sendStandaloneAck(p *packet) {
	ackPkt := p.NewStandaloneAck()
	if p.session != nil && p.session.ID != 0 {
		ackPkt.AssignMessageCounter(p.session)
		ackPkt.EncryptAndAuthenticate(p.session.EncryptionKey)
	} else if p.session != nil {
		ackPkt.AssignMessageCounter(p.session)
	}

	select {
	case m.outbound <- ackPkt:
		m.logger.Debug("MRP: sent standalone ACK (immediate)", "exchangeID", p.protocolHeader.ExchangeID)
	default:
	}
}
