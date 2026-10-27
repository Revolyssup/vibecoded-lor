package probe

import (
	"net"
	"sync"
	"time"
)

// tapConn reports every chunk of bytes read from or written to a connection.
type tapConn struct {
	net.Conn
	onRead  func([]byte, time.Time)
	onWrite func([]byte, time.Time)
}

func (c *tapConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.onRead != nil {
		c.onRead(b[:n], time.Now())
	}
	return n, err
}

func (c *tapConn) Write(b []byte) (int, error) {
	ts := time.Now() // the bytes hit the wire during Write, not after it
	n, err := c.Conn.Write(b)
	if n > 0 && c.onWrite != nil {
		c.onWrite(b[:n], ts)
	}
	return n, err
}

// firstRead calls fn once, on the first successful read after arm().
type firstRead struct {
	mu    sync.Mutex
	armed bool
	fn    func()
}

func (f *firstRead) arm(fn func()) {
	f.mu.Lock()
	f.armed, f.fn = true, fn
	f.mu.Unlock()
}

func (f *firstRead) hit() {
	f.mu.Lock()
	fn := f.fn
	if !f.armed {
		fn = nil
	}
	f.armed, f.fn = false, nil
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
}
