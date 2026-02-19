package matter

import "sync"

// ServeMux is a simple request multiplexer.
// It matches the incoming message (as a string) against a list of registered patterns.
type ServeMux struct {
	mu sync.RWMutex
	m  map[string]Handler
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{m: make(map[string]Handler)}
}

// Handle registers the handler for the given pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if pattern == "" {
		panic("matter: invalid pattern")
	}
	if handler == nil {
		panic("matter: nil handler")
	}
	if _, exist := mux.m[pattern]; exist {
		panic("matter: multiple registrations for " + pattern)
	}
	mux.m[pattern] = handler
}

// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(*ExchangeContext)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// Serve dispatches the request to the handler whose pattern matches the request message.
func (mux *ServeMux) Serve(ctx *ExchangeContext) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	// Phase 1: Simple exact string matching
	reqStr := string(ctx.Request)
	if h, ok := mux.m[reqStr]; ok {
		h.Serve(ctx)
	}
	// TODO: Handle 404 / Unknown command
}
