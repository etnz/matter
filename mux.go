package matter

import (
	"sync"

	"github.com/tom-code/gomat"
)

// ServeMux is a simple request multiplexer.
// It matches the incoming message against a list of registered patterns.
type ServeMux struct {
	mu sync.RWMutex
	m  map[gomat.ProtocolId]map[gomat.Opcode]Handler
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{m: make(map[gomat.ProtocolId]map[gomat.Opcode]Handler)}
}

// Handle registers the handler for the given pattern.
func (mux *ServeMux) Handle(proto gomat.ProtocolId, opcode gomat.Opcode, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if handler == nil {
		panic("matter: nil handler")
	}
	if mux.m[proto] == nil {
		mux.m[proto] = make(map[gomat.Opcode]Handler)
	}
	mux.m[proto][opcode] = handler
}

// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(proto gomat.ProtocolId, opcode gomat.Opcode, handler func(*ExchangeContext)) {
	mux.Handle(proto, opcode, HandlerFunc(handler))
}

// Serve dispatches the request to the handler whose pattern matches the request message.
func (mux *ServeMux) Serve(ctx *ExchangeContext) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	if ops, ok := mux.m[ctx.ProtocolMessageHeader.ProtocolId]; ok {
		if h, ok := ops[ctx.ProtocolMessageHeader.Opcode]; ok {
			h.Serve(ctx)
		}
	}
	// TODO: Handle 404 / Unknown command
}
