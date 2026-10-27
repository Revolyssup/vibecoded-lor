package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// TLSOptions configures the client side of the handshake.
type TLSOptions struct {
	ServerName string
	Insecure   bool
	ALPN       []string
	KeyLog     io.Writer
}

// tapTLS wraps raw so every TLS record is decoded into events.
func tapTLS(tr *trace.Tracer, raw net.Conn, st *tlsState) net.Conn {
	outS := &tlsStream{dir: trace.DirOut, tr: tr, state: st}
	inS := &tlsStream{dir: trace.DirIn, tr: tr, state: st}
	return &tapConn{Conn: raw,
		onWrite: func(b []byte, ts time.Time) { outS.feed(b, ts) },
		onRead:  func(b []byte, ts time.Time) { inS.feed(b, ts) },
	}
}

func handshakeTLS(ctx context.Context, tr *trace.Tracer, raw net.Conn, o TLSOptions) (*tlsConn, error) {
	st := &tlsState{}
	// Verification is done by hand in VerifyConnection so the certificate
	// can be shown even when it is rejected.
	cfg := &tls.Config{
		ServerName:         o.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         o.ALPN,
		KeyLogWriter:       o.KeyLog,
		VerifyConnection: func(cs tls.ConnectionState) error {
			secs := certSections(cs.PeerCertificates)
			if o.Insecure {
				tr.Emit(trace.Event{Layer: trace.LayerTLS, Dir: trace.DirIn, Title: "TLS server certificate received (NOT verified, -k)", Warn: true, Sections: secs})
				return nil
			}
			if err := verify(cs.PeerCertificates, o.ServerName); err != nil {
				tr.Emit(trace.Event{Layer: trace.LayerTLS, Dir: trace.DirIn, Title: "TLS server certificate rejected", Warn: true, Note: err.Error(), Sections: secs})
				return err
			}
			tr.Emit(trace.Event{Layer: trace.LayerTLS, Dir: trace.DirIn, Title: "TLS server certificate verified", Sections: secs})
			return nil
		},
	}
	tc := tls.Client(tapTLS(tr, raw, st), cfg)
	tr.PhaseStart("TLS handshake")
	err := tc.HandshakeContext(ctx)
	st.handshakeDone.Store(true)
	tr.PhaseEnd("TLS handshake")
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerTLS, Title: "TLS handshake failed", Warn: true, Note: err.Error(),
			Sections: []trace.Section{{Layer: trace.LayerTLS, Title: "Handshake error", Fields: []trace.Field{{K: "Error", V: err.Error()}}}}})
		return nil, err
	}
	cs := tc.ConnectionState()
	alpn := cs.NegotiatedProtocol
	if alpn == "" {
		alpn = "(none)"
	}
	sec := trace.Section{Layer: trace.LayerTLS, Title: "Secure session", Fields: []trace.Field{
		{K: "Version", V: versionName(cs.Version)},
		{K: "Cipher suite", V: tls.CipherSuiteName(cs.CipherSuite)},
		{K: "SNI", V: orNone(cs.ServerName)},
		{K: "ALPN", V: alpn},
		{K: "Resumed", V: fmt.Sprint(cs.DidResume)},
	}, Detail: []trace.Field{
		{K: "OCSP stapled", V: fmt.Sprint(len(cs.OCSPResponse) > 0)},
		{K: "SCTs", V: fmt.Sprint(len(cs.SignedCertificateTimestamps))},
	}}
	tr.Emit(trace.Event{Layer: trace.LayerTLS, Title: "TLS handshake complete", Sections: append([]trace.Section{sec}, certSections(cs.PeerCertificates)...)})
	return &tlsConn{Conn: tc, st: st}, nil
}

// tlsConn marks the stream as closing so the final alert is labelled.
type tlsConn struct {
	*tls.Conn
	st *tlsState
}

func (c *tlsConn) Close() error {
	c.st.closing.Store(true)
	return c.Conn.Close()
}

func verify(chain []*x509.Certificate, host string) error {
	if len(chain) == 0 {
		return errors.New("server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return err
}

func certSections(chain []*x509.Certificate) []trace.Section {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	left := time.Until(leaf.NotAfter)
	validity := fmt.Sprintf("%s (%d days left)", leaf.NotAfter.Format("2006-01-02"), int(left.Hours()/24))
	if left < 0 {
		validity = fmt.Sprintf("%s (EXPIRED)", leaf.NotAfter.Format("2006-01-02"))
	}
	sans := leaf.DNSNames
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	sanText := strings.Join(sans, ", ")
	if len(sans) > 4 {
		sanText = strings.Join(sans[:4], ", ") + fmt.Sprintf(" +%d more", len(sans)-4)
	}
	var chainLines []string
	for i, c := range chain {
		chainLines = append(chainLines, fmt.Sprintf("%d. %s", i, name(c.Subject.CommonName, c.Subject.String())))
	}
	return []trace.Section{{Layer: trace.LayerTLS, Title: "Server certificate", Fields: []trace.Field{
		{K: "Subject", V: name(leaf.Subject.CommonName, leaf.Subject.String())},
		{K: "Issuer", V: name(leaf.Issuer.CommonName, leaf.Issuer.String())},
		{K: "Valid until", V: validity},
		{K: "SANs", V: orNone(sanText)},
	}, Detail: []trace.Field{
		{K: "Public key", V: keyDesc(leaf)},
		{K: "Signature", V: leaf.SignatureAlgorithm.String()},
		{K: "Valid from", V: leaf.NotBefore.Format("2006-01-02")},
		{K: "Chain", V: strings.Join(chainLines, "  ")},
	}}}
}

func name(cn, full string) string {
	if cn != "" {
		return cn
	}
	return full
}

func keyDesc(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}
