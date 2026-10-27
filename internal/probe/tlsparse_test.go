package probe

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

func TestClientHelloIsDecoded(t *testing.T) {
	client, server := net.Pipe()
	tr := trace.New()
	st := &tlsState{}
	tapped := tapTLS(tr, client, st)
	go func() {
		tls.Client(tapped, &tls.Config{ServerName: "example.test", NextProtos: []string{"http/1.1"}}).Handshake()
	}()
	buf := make([]byte, 4096)
	server.Read(buf) // the ClientHello flight
	server.Close()

	ev := (<-tr.C()).(trace.Event)
	if ev.Title != "TLS ClientHello" || ev.Dir != trace.DirOut {
		t.Fatalf("got %q dir %v", ev.Title, ev.Dir)
	}
	got := map[string]string{}
	for _, f := range ev.Sections[0].Fields {
		got[f.K] = f.V
	}
	if got["SNI"] != "example.test" {
		t.Errorf("SNI = %q", got["SNI"])
	}
	if got["ALPN offered"] != "http/1.1" {
		t.Errorf("ALPN = %q", got["ALPN offered"])
	}
	if got["Versions offered"] != "TLS 1.3, TLS 1.2" {
		t.Errorf("versions = %q", got["Versions offered"])
	}
}

func TestNonTLSStreamIsIgnored(t *testing.T) {
	tr := trace.New()
	s := &tlsStream{dir: trace.DirIn, tr: tr, state: &tlsState{}}
	s.feed([]byte("HTTP/1.1 200 OK\r\n\r\n"), time.Now())
	if !s.broken {
		t.Fatal("expected plaintext to be rejected")
	}
	select {
	case m := <-tr.C():
		t.Fatalf("unexpected event %v", m)
	default:
	}
}
