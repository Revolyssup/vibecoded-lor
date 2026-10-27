// Package trace defines the events and timing phases that flow from the
// probes (request runner, packet capture) to the user interface.
package trace

import (
	"sync"
	"time"
)

// Layer identifies where in the network stack an event happened.
type Layer int

const (
	LayerNone Layer = iota
	LayerDNS
	LayerIP
	LayerTCP
	LayerTLS
	LayerHTTP
	LayerApp // raw application payload (tcp mode)
)

func (l Layer) String() string {
	switch l {
	case LayerDNS:
		return "DNS"
	case LayerIP:
		return "IP"
	case LayerTCP:
		return "TCP"
	case LayerTLS:
		return "TLS"
	case LayerHTTP:
		return "HTTP"
	case LayerApp:
		return "DATA"
	}
	return "INFO"
}

// Dir is the direction of an event relative to the client.
type Dir int

const (
	DirNone Dir = iota
	DirOut      // client -> server
	DirIn       // server -> client
)

func (d Dir) Arrow() string {
	switch d {
	case DirOut:
		return "→"
	case DirIn:
		return "←"
	}
	return "•"
}

// Field is one human readable key/value line of a layer.
type Field struct {
	K, V string
}

// Section is what one layer looked like at the time of an event.
// Fields are the headline values shown in the stack diagram; Detail holds
// the less important ones, shown only when the user asks for detail.
type Section struct {
	Layer  Layer
	Title  string
	Fields []Field
	Detail []Field
	Text   string // optional preformatted block (headers, payload preview)
}

// Source says how an event was observed.
type Source string

const (
	SrcWire   Source = "wire"   // captured packet
	SrcSocket Source = "socket" // observed from the client socket / library
)

// Event is a single thing that happened during the request lifecycle.
type Event struct {
	At       time.Duration // since the trace started
	Layer    Layer
	Dir      Dir
	Source   Source
	Title    string
	Note     string
	Warn     bool
	Sections []Section
}

// Phase is a timed span used for the waterfall.
type Phase struct {
	Name       string
	Start, End time.Duration
	Done       bool
}

// Msg is anything sent on the trace channel: Event, Phase, Info or Done.
type Msg interface{}

// Info describes the run itself (target, capture mode) for the UI header.
type Info struct {
	Target  string
	Capture string
}

// Done is the final message of a trace.
type Done struct {
	Err     error
	Summary []Field
	Body    []byte // response preview, for plain mode output
}

// Tracer timestamps events and phases and hands them to the UI.
type Tracer struct {
	start time.Time
	ch    chan Msg

	mu     sync.Mutex
	phases map[string]*Phase
	closed bool
}

func New() *Tracer {
	return &Tracer{start: time.Now(), ch: make(chan Msg, 4096), phases: map[string]*Phase{}}
}

func (t *Tracer) C() <-chan Msg                 { return t.ch }
func (t *Tracer) Start() time.Time              { return t.start }
func (t *Tracer) Now() time.Duration            { return time.Since(t.start) }
func (t *Tracer) At(ts time.Time) time.Duration { return ts.Sub(t.start) }

func (t *Tracer) send(m Msg) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.ch <- m
	}
}

// Emit publishes an event. Events without a timestamp get "now".
func (t *Tracer) Emit(e Event) {
	if e.At == 0 {
		e.At = t.Now()
	}
	if e.Source == "" {
		e.Source = SrcSocket
	}
	t.send(e)
}

func (t *Tracer) SetInfo(i Info) { t.send(i) }

func (t *Tracer) PhaseStart(name string) {
	t.mu.Lock()
	p := &Phase{Name: name, Start: t.Now()}
	t.phases[name] = p
	cp := *p
	t.mu.Unlock()
	t.send(cp)
}

func (t *Tracer) PhaseEnd(name string) {
	t.mu.Lock()
	p, ok := t.phases[name]
	if !ok || p.Done {
		t.mu.Unlock()
		return
	}
	p.End, p.Done = t.Now(), true
	cp := *p
	t.mu.Unlock()
	t.send(cp)
}

// Finish ends any open phase, sends Done and closes the channel.
func (t *Tracer) Finish(d Done) {
	t.mu.Lock()
	open := []string{}
	for n, p := range t.phases {
		if !p.Done {
			open = append(open, n)
		}
	}
	t.mu.Unlock()
	for _, n := range open {
		t.PhaseEnd(n)
	}
	t.send(d)
	t.mu.Lock()
	t.closed = true
	close(t.ch)
	t.mu.Unlock()
}
