package probe

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// tlsStream decodes the TLS record layer of one direction of a connection
// from the raw bytes going over the socket and emits an event per record.
type tlsStream struct {
	dir       trace.Dir
	tr        *trace.Tracer
	buf       []byte
	hs        []byte // handshake message reassembly
	encrypted bool   // handshake records are encrypted from here on
	nEnc      int    // encrypted handshake records seen so far
	broken    bool   // not TLS, stop parsing
	state     *tlsState
	ts        time.Time // when the bytes being parsed were sent or received
}

// tlsState is shared by both directions.
type tlsState struct {
	tls13         atomic.Bool
	handshakeDone atomic.Bool
	closing       atomic.Bool
}

var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func (s *tlsStream) feed(b []byte, ts time.Time) {
	if s.broken {
		return
	}
	s.ts = ts
	s.buf = append(s.buf, b...)
	for len(s.buf) >= 5 {
		typ := s.buf[0]
		if typ < 20 || typ > 24 {
			s.broken = true
			return
		}
		n := int(binary.BigEndian.Uint16(s.buf[3:5]))
		if len(s.buf) < 5+n {
			return
		}
		ver := binary.BigEndian.Uint16(s.buf[1:3])
		body := s.buf[5 : 5+n]
		s.record(typ, ver, body)
		s.buf = s.buf[5+n:]
	}
}

func recordSection(typ byte, ver uint16, n int) trace.Section {
	return trace.Section{Layer: trace.LayerTLS, Title: "Record layer", Fields: []trace.Field{
		{K: "Content type", V: contentTypeName(typ)},
		{K: "Record version", V: versionName(ver)},
		{K: "Length", V: fmt.Sprintf("%d bytes", n)},
	}}
}

func (s *tlsStream) emit(title string, warn bool, secs ...trace.Section) {
	s.tr.Emit(trace.Event{At: s.tr.At(s.ts), Layer: trace.LayerTLS, Dir: s.dir, Title: title, Warn: warn, Sections: secs})
}

func (s *tlsStream) record(typ byte, ver uint16, body []byte) {
	rec := recordSection(typ, ver, len(body))
	switch typ {
	case 20:
		s.encrypted = true
		note := "switching to negotiated keys"
		if s.state.tls13.Load() {
			note = "dummy record for middlebox compatibility (TLS 1.3)"
		}
		rec.Fields = append(rec.Fields, trace.Field{K: "Meaning", V: note})
		s.emit("TLS ChangeCipherSpec", false, rec)
	case 21:
		if s.encrypted || s.state.handshakeDone.Load() || len(body) < 2 {
			s.emit("TLS Alert (encrypted)", false, rec)
			return
		}
		level := "warning"
		if body[0] == 2 {
			level = "fatal"
		}
		rec.Fields = append(rec.Fields, trace.Field{K: "Alert", V: fmt.Sprintf("%s: %s", level, alertName(body[1]))})
		s.emit("TLS Alert: "+alertName(body[1]), body[0] == 2, rec)
	case 22:
		if s.encrypted {
			s.emit("TLS encrypted handshake message", false, rec)
			return
		}
		s.hs = append(s.hs, body...)
		for len(s.hs) >= 4 {
			mt := s.hs[0]
			ml := int(s.hs[1])<<16 | int(s.hs[2])<<8 | int(s.hs[3])
			if len(s.hs) < 4+ml {
				break
			}
			s.handshake(mt, s.hs[4:4+ml], rec)
			s.hs = s.hs[4+ml:]
		}
	case 23:
		if !s.state.handshakeDone.Load() {
			rec.Fields = append(rec.Fields, trace.Field{K: "Carries", V: encryptedFlight(s.dir)})
			s.emit("TLS encrypted handshake"+s.guess(), false, rec)
			return
		}
		if s.state.closing.Load() && s.dir == trace.DirOut {
			rec.Fields = append(rec.Fields, trace.Field{K: "Carries", V: "close_notify alert (encrypted)"})
			s.emit("TLS close_notify (encrypted alert)", false, rec)
			return
		}
		rec.Fields = append(rec.Fields, trace.Field{K: "Carries", V: "encrypted application data"})
		s.emit(fmt.Sprintf("TLS ApplicationData %dB", len(body)), false, rec)
	default:
		s.emit("TLS record type "+fmt.Sprint(typ), false, rec)
	}
}

func (s *tlsStream) guess() string {
	s.nEnc++
	return fmt.Sprintf(" #%d", s.nEnc)
}

func encryptedFlight(d trace.Dir) string {
	if d == trace.DirIn {
		return "EncryptedExtensions, Certificate, CertificateVerify, Finished"
	}
	return "client Finished"
}

func (s *tlsStream) handshake(mt byte, m []byte, rec trace.Section) {
	switch mt {
	case 1:
		sec := parseClientHello(m)
		s.emit("TLS ClientHello", false, sec, rec)
	case 2:
		sec, v13, hrr := parseServerHello(m)
		if v13 {
			s.state.tls13.Store(true)
			if !hrr {
				s.encrypted = true
			}
		}
		title := "TLS ServerHello"
		if hrr {
			title = "TLS HelloRetryRequest"
		}
		s.emit(title, false, sec, rec)
	case 11:
		n := 0
		if len(m) >= 3 {
			rest := m[3:]
			for len(rest) >= 3 {
				l := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
				if len(rest) < 3+l {
					break
				}
				n++
				rest = rest[3+l:]
			}
		}
		s.emit("TLS Certificate", false, trace.Section{Layer: trace.LayerTLS, Title: "Certificate",
			Fields: []trace.Field{{K: "Chain length", V: fmt.Sprint(n)}}}, rec)
	case 12:
		f := []trace.Field{}
		if len(m) >= 3 && m[0] == 3 {
			f = append(f, trace.Field{K: "Key exchange group", V: groupName(binary.BigEndian.Uint16(m[1:3]))})
		}
		s.emit("TLS ServerKeyExchange", false, trace.Section{Layer: trace.LayerTLS, Title: "ServerKeyExchange", Fields: f}, rec)
	case 13:
		s.emit("TLS CertificateRequest", false, rec)
	case 14:
		s.emit("TLS ServerHelloDone", false, rec)
	case 16:
		s.emit("TLS ClientKeyExchange", false, rec)
	case 20:
		s.emit("TLS Finished", false, rec)
	case 4:
		s.emit("TLS NewSessionTicket", false, rec)
	default:
		s.emit(fmt.Sprintf("TLS handshake message %d", mt), false, rec)
	}
}

// reader is a tiny bounds-checked cursor for parsing hello messages.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}
func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (r *reader) vec8() []byte  { return r.take(r.u8()) }
func (r *reader) vec16() []byte { return r.take(r.u16()) }

type ext struct {
	typ  int
	data []byte
}

func parseExts(b []byte) []ext {
	r := &reader{b: b}
	var out []ext
	for len(r.b) >= 4 && !r.bad {
		t := r.u16()
		out = append(out, ext{t, r.vec16()})
	}
	return out
}

func parseClientHello(m []byte) trace.Section {
	r := &reader{b: m}
	legacy := r.u16()
	r.take(32)
	r.vec8()
	cs := r.vec16()
	r.vec8()
	exts := parseExts(r.vec16())

	var ciphers []string
	for i := 0; i+1 < len(cs); i += 2 {
		v := binary.BigEndian.Uint16(cs[i:])
		if isGrease(v) {
			continue
		}
		ciphers = append(ciphers, tls.CipherSuiteName(v))
	}
	sni, alpn, versions, groups, shares, names := "", []string{}, []string{}, []string{}, []string{}, []string{}
	for _, e := range exts {
		names = append(names, extName(e.typ))
		er := &reader{b: e.data}
		switch e.typ {
		case 0:
			l := &reader{b: er.vec16()}
			for len(l.b) > 0 && !l.bad {
				t := l.u8()
				n := l.vec16()
				if t == 0 {
					sni = string(n)
				}
			}
		case 16:
			l := &reader{b: er.vec16()}
			for len(l.b) > 0 && !l.bad {
				alpn = append(alpn, string(l.vec8()))
			}
		case 43:
			l := er.vec8()
			for i := 0; i+1 < len(l); i += 2 {
				if v := binary.BigEndian.Uint16(l[i:]); !isGrease(v) {
					versions = append(versions, versionName(v))
				}
			}
		case 10:
			l := er.vec16()
			for i := 0; i+1 < len(l); i += 2 {
				if v := binary.BigEndian.Uint16(l[i:]); !isGrease(v) {
					groups = append(groups, groupName(v))
				}
			}
		case 51:
			l := &reader{b: er.vec16()}
			for len(l.b) > 0 && !l.bad {
				g := uint16(l.u16())
				l.vec16()
				if !isGrease(g) {
					shares = append(shares, groupName(g))
				}
			}
		}
	}
	if len(versions) == 0 {
		versions = []string{versionName(uint16(legacy))}
	}
	if sni == "" {
		sni = "(none)"
	}
	return trace.Section{Layer: trace.LayerTLS, Title: "ClientHello", Fields: []trace.Field{
		{K: "SNI", V: sni},
		{K: "Versions offered", V: strings.Join(versions, ", ")},
		{K: "ALPN offered", V: orNone(strings.Join(alpn, ", "))},
		{K: "Cipher suites", V: fmt.Sprintf("%d offered", len(ciphers))},
		{K: "Key shares", V: orNone(strings.Join(shares, ", "))},
	}, Detail: []trace.Field{
		{K: "Ciphers", V: strings.Join(ciphers, ", ")},
		{K: "Groups", V: strings.Join(groups, ", ")},
		{K: "Extensions", V: strings.Join(names, ", ")},
	}}
}

func parseServerHello(m []byte) (sec trace.Section, tls13, hrr bool) {
	r := &reader{b: m}
	legacy := uint16(r.u16())
	random := r.take(32)
	r.vec8()
	cs := uint16(r.u16())
	r.u8()
	exts := parseExts(r.vec16())
	hrr = bytes.Equal(random, helloRetryRandom)
	ver := legacy
	group := ""
	alpn := ""
	var names []string
	for _, e := range exts {
		names = append(names, extName(e.typ))
		er := &reader{b: e.data}
		switch e.typ {
		case 43:
			ver = uint16(er.u16())
		case 51:
			group = groupName(uint16(er.u16()))
		case 16:
			l := &reader{b: er.vec16()}
			alpn = string(l.vec8())
		}
	}
	tls13 = ver == tls.VersionTLS13
	f := []trace.Field{
		{K: "Version", V: versionName(ver)},
		{K: "Cipher suite", V: tls.CipherSuiteName(cs)},
	}
	if group != "" {
		f = append(f, trace.Field{K: "Key share", V: group})
	}
	if alpn != "" {
		f = append(f, trace.Field{K: "ALPN", V: alpn})
	}
	if tls13 && !hrr {
		f = append(f, trace.Field{K: "Next", V: "everything after this is encrypted"})
	}
	return trace.Section{Layer: trace.LayerTLS, Title: "ServerHello", Fields: f,
		Detail: []trace.Field{{K: "Extensions", V: strings.Join(names, ", ")}}}, tls13, hrr
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func contentTypeName(t byte) string {
	switch t {
	case 20:
		return "ChangeCipherSpec (20)"
	case 21:
		return "Alert (21)"
	case 22:
		return "Handshake (22)"
	case 23:
		return "ApplicationData (23)"
	}
	return fmt.Sprintf("%d", t)
}

func versionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func groupName(g uint16) string {
	switch g {
	case 23:
		return "P-256"
	case 24:
		return "P-384"
	case 25:
		return "P-521"
	case 29:
		return "X25519"
	case 30:
		return "X448"
	case 0x11ec:
		return "X25519MLKEM768"
	case 0x6399:
		return "X25519Kyber768Draft00"
	}
	return fmt.Sprintf("0x%04x", g)
}

func extName(t int) string {
	switch t {
	case 0:
		return "server_name"
	case 5:
		return "status_request"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 16:
		return "alpn"
	case 18:
		return "sct"
	case 23:
		return "extended_master_secret"
	case 35:
		return "session_ticket"
	case 41:
		return "pre_shared_key"
	case 43:
		return "supported_versions"
	case 45:
		return "psk_key_exchange_modes"
	case 51:
		return "key_share"
	case 65281:
		return "renegotiation_info"
	}
	if isGrease(uint16(t)) {
		return "GREASE"
	}
	return fmt.Sprint(t)
}

func alertName(d byte) string {
	names := map[byte]string{0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
		42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
		46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error", 51: "decrypt_error",
		70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 90: "user_canceled",
		109: "missing_extension", 112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol"}
	if n, ok := names[d]; ok {
		return n
	}
	return fmt.Sprint(d)
}
