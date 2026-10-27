package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// TCPOptions describes a raw TCP (optionally TLS) exchange.
type TCPOptions struct {
	Addr        string // host:port
	Data        []byte
	TLS         bool
	ServerName  string
	Insecure    bool
	KeyLog      io.Writer
	Output      io.Writer
	ReadTimeout time.Duration // stop reading after this much silence
	Dial        DialOptions
	Timeout     time.Duration
}

func RunTCP(tr *trace.Tracer, o TCPOptions) {
	sum, pv, err := runTCP(tr, o)
	tr.Finish(trace.Done{Err: err, Body: pv, Summary: sum})
}

func runTCP(tr *trace.Tracer, o TCPOptions) ([]trace.Field, []byte, error) {
	host, ps, err := net.SplitHostPort(o.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("want host:port, got %q", o.Addr)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, nil, fmt.Errorf("bad port %q", ps)
	}
	scheme := "tcp"
	if o.TLS {
		scheme = "tls"
	}
	tr.SetInfo(trace.Info{Target: scheme + "://" + o.Addr})
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	l, err := dial(ctx, tr, host, port, o.Dial)
	if err != nil {
		return nil, nil, err
	}
	defer l.stop(300 * time.Millisecond)
	sum := []trace.Field{{K: "Connected to", V: l.remote.String()}}

	var conn net.Conn = l.conn
	if o.TLS {
		sni := o.ServerName
		if sni == "" {
			sni = host
		}
		tc, err := handshakeTLS(ctx, tr, l.conn, TLSOptions{ServerName: sni, Insecure: o.Insecure, KeyLog: o.KeyLog})
		if err != nil {
			l.conn.Close()
			return sum, nil, err
		}
		conn = tc
	}
	defer func() {
		socketStats(tr, l)
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirOut, Title: "Closing connection"})
		conn.Close()
	}()

	if len(o.Data) > 0 {
		tr.PhaseStart("Send")
		_, err := conn.Write(o.Data)
		tr.PhaseEnd("Send")
		if err != nil {
			return sum, nil, err
		}
		tr.Emit(trace.Event{Layer: trace.LayerApp, Dir: trace.DirOut, Title: fmt.Sprintf("Sent %d bytes", len(o.Data)),
			Sections: []trace.Section{payloadSection("Sent", o.Data, len(o.Data))}})
	}

	tr.PhaseStart("Waiting for reply")
	waiting := true
	var got []byte
	total := 0
	buf := make([]byte, 32<<10)
	for {
		conn.SetReadDeadline(time.Now().Add(o.ReadTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			if waiting {
				tr.PhaseEnd("Waiting for reply")
				tr.PhaseStart("Receive")
				waiting = false
			}
			total += n
			if len(got) < previewLimit {
				got = append(got, buf[:min(n, previewLimit-len(got))]...)
			}
			if o.Output != nil {
				o.Output.Write(buf[:n])
			}
			tr.Emit(trace.Event{Layer: trace.LayerApp, Dir: trace.DirIn, Title: fmt.Sprintf("Received %d bytes", n),
				Sections: []trace.Section{payloadSection("Received", got, total)}})
		}
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded):
				tr.Emit(trace.Event{Title: fmt.Sprintf("No data for %s, done reading", o.ReadTimeout)})
			case errors.Is(err, io.EOF):
				tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirIn, Title: "Server closed the connection (EOF)"})
			default:
				tr.Emit(trace.Event{Title: "Read error", Warn: true, Note: err.Error()})
				return sum, got, err
			}
			break
		}
	}
	tr.PhaseEnd("Waiting for reply")
	tr.PhaseEnd("Receive")
	return append(sum, trace.Field{K: "Total time", V: tr.Now().Round(time.Microsecond).String()},
		trace.Field{K: "Received", V: fmt.Sprintf("%d bytes", total)}), got, nil
}

func payloadSection(title string, b []byte, total int) trace.Section {
	return trace.Section{Layer: trace.LayerApp, Title: title, Fields: []trace.Field{{K: "Bytes", V: fmt.Sprint(total)}},
		Text: dump(b)}
}

// dump shows text as text and anything else as a short hex dump.
func dump(b []byte) string {
	p := printable(b)
	if !strings.HasPrefix(p, "(binary") {
		return p
	}
	b = b[:min(len(b), 128)]
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		row := b[i:min(i+16, len(b))]
		fmt.Fprintf(&sb, "%04x  %-48s ", i, fmt.Sprintf("% x", row))
		for _, c := range row {
			if c < 32 || c > 126 {
				c = '.'
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}
