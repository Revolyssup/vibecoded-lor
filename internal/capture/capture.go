// Package capture watches the packets of one TCP connection on the wire and
// turns them into stack events: IP and TCP headers, decoded for humans.
package capture

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// ErrUnsupported is returned on platforms without a capture backend.
var ErrUnsupported = errors.New("packet capture is not supported on this platform yet")

type Options struct {
	Disabled bool
	Iface    string // empty: all interfaces
}

// packet is one layer 3 packet from a platform source.
type packet struct {
	data     []byte
	ts       time.Time
	outgoing bool
	ifindex  int
}

// source is a platform packet source. next blocks for a short while and
// returns a nil packet on timeout.
type source interface {
	next() (*packet, error)
	close()
}

type target struct {
	tr     *trace.Tracer
	remote netip.AddrPort
}

// Capturer reads packets from the moment it is opened, and turns those of
// the watched connection into events once Watch is called.
type Capturer struct {
	desc      string
	loIndex   int
	src       source
	tgt       atomic.Pointer[target]
	localPort atomic.Uint32
	dec       decoder
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// Open starts the packet source. It is called before the request starts so
// that setting up capture does not show up in the timings.
func Open(o Options) (*Capturer, error) {
	if o.Disabled {
		return nil, errors.New("disabled by --no-capture")
	}
	idx, desc := 0, "all interfaces"
	if o.Iface != "" {
		ifc, err := net.InterfaceByName(o.Iface)
		if err != nil {
			return nil, err
		}
		idx, desc = ifc.Index, ifc.Name
	}
	src, err := open(idx)
	if err != nil {
		return nil, err
	}
	c := &Capturer{desc: "capturing packets on " + desc, src: src, stop: make(chan struct{}), done: make(chan struct{})}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Flags&net.FlagLoopback != 0 {
				c.loIndex = i.Index
			}
		}
	}
	c.dec.init()
	go c.loop()
	return c, nil
}

func (c *Capturer) Describe() string { return c.desc }

// Watch selects the connection to the remote address to report on.
func (c *Capturer) Watch(remote netip.AddrPort, tr *trace.Tracer) {
	c.tgt.Store(&target{tr: tr, remote: remote})
}

func (c *Capturer) SetLocalPort(p int) { c.localPort.Store(uint32(p)) }

// Stop ends the capture and waits for the reader to exit.
func (c *Capturer) Stop() {
	c.stopOnce.Do(func() { close(c.stop) })
	<-c.done
}

func (c *Capturer) loop() {
	defer close(c.done)
	defer c.src.close()
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		p, err := c.src.next()
		t := c.tgt.Load()
		if err != nil {
			if t != nil {
				t.tr.Emit(trace.Event{Title: "Packet capture stopped: " + err.Error(), Warn: true})
			}
			return
		}
		if p == nil || t == nil {
			continue
		}
		// On loopback every packet is seen twice (out and back in). Keep the
		// outgoing copy: it is stamped when the packet is sent.
		if p.ifindex == c.loIndex && !p.outgoing {
			continue
		}
		if ev, ok := c.dec.decode(p.data, t.remote, uint16(c.localPort.Load())); ok {
			ev.At = t.tr.At(p.ts)
			ev.Source = trace.SrcWire
			t.tr.Emit(ev)
		}
	}
}
