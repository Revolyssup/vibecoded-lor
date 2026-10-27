package probe

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// HTTPOptions describes one HTTP/1.1 request.
type HTTPOptions struct {
	Method   string
	URL      string
	Headers  []string // "Name: value"
	Body     []byte
	Insecure bool
	KeyLog   io.Writer
	Output   io.Writer // receives the response body, may be nil
	Dial     DialOptions
	Timeout  time.Duration
}

const previewLimit = 4096

// RunHTTP performs the request, emitting events as it goes, and finishes tr.
func RunHTTP(tr *trace.Tracer, o HTTPOptions) {
	res, err := runHTTP(tr, o)
	if res.total == 0 {
		res.total = tr.Now()
	}
	sum := []trace.Field{{K: "Total time", V: res.total.Round(time.Microsecond).String()}}
	sum = append(sum, res.summary...)
	tr.Finish(trace.Done{Err: err, Summary: sum, Body: res.preview})
}

type httpResult struct {
	total   time.Duration // until the body was read, before teardown
	summary []trace.Field
	preview []byte
}

func runHTTP(tr *trace.Tracer, o HTTPOptions) (res httpResult, err error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return res, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return res, fmt.Errorf("unsupported scheme %q (use http:// or https://, or `lor tcp`)", u.Scheme)
	}
	tr.SetInfo(trace.Info{Target: o.Method + " " + u.String()})
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return res, fmt.Errorf("bad port %q", p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()

	l, err := dial(ctx, tr, u.Hostname(), port, o.Dial)
	if err != nil {
		return res, err
	}
	defer l.stop(300 * time.Millisecond)
	defer func() {
		if res.total == 0 {
			res.total = tr.Now()
		}
	}()
	if dl, ok := ctx.Deadline(); ok {
		l.conn.SetDeadline(dl)
	}
	res.summary = append(res.summary, trace.Field{K: "Connected to", V: l.remote.String()})

	var conn net.Conn = l.conn
	if u.Scheme == "https" {
		tc, err := handshakeTLS(ctx, tr, l.conn, TLSOptions{ServerName: u.Hostname(), Insecure: o.Insecure, ALPN: []string{"http/1.1"}, KeyLog: o.KeyLog})
		if err != nil {
			l.conn.Close()
			return res, err
		}
		conn = tc
	}
	var fr firstRead
	app := &tapConn{Conn: conn, onRead: func([]byte, time.Time) { fr.hit() }}
	defer func() {
		socketStats(tr, l)
		title := "Closing connection (FIN)"
		if u.Scheme == "https" {
			title = "Closing connection (TLS close_notify, then FIN)"
		}
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirOut, Title: title})
		app.Close()
	}()

	var body io.Reader
	if o.Body != nil {
		body = bytes.NewReader(o.Body)
	}
	req, err := http.NewRequest(o.Method, u.String(), body)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "lor/0.1")
	req.Header.Set("Accept", "*/*")
	for _, h := range o.Headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return res, fmt.Errorf("bad header %q, want 'Name: value'", h)
		}
		if strings.EqualFold(strings.TrimSpace(k), "host") {
			req.Host = strings.TrimSpace(v)
			continue
		}
		req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}

	tr.PhaseStart("Request sent")
	wstart := time.Now()
	var head bytes.Buffer
	bw := bufio.NewWriter(io.MultiWriter(app, &headCapture{buf: &head}))
	if err = req.Write(bw); err == nil {
		err = bw.Flush()
	}
	tr.PhaseEnd("Request sent")
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirOut, Title: "HTTP request write failed", Warn: true, Note: err.Error()})
		return res, err
	}
	tr.PhaseStart("Server processing")
	fr.arm(func() {
		tr.PhaseEnd("Server processing")
		tr.PhaseStart("Content download")
		tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirIn, Title: "HTTP first byte received (TTFB)"})
	})
	reqLine, reqHeaders, _ := strings.Cut(head.String(), "\r\n")
	tr.Emit(trace.Event{At: tr.At(wstart), Layer: trace.LayerHTTP, Dir: trace.DirOut, Title: "HTTP request sent: " + req.Method + " " + req.URL.RequestURI(),
		Sections: []trace.Section{{Layer: trace.LayerHTTP, Title: "Request", Fields: []trace.Field{
			{K: "Request line", V: reqLine},
			{K: "Host", V: req.Host},
			{K: "Body", V: fmt.Sprintf("%d bytes", len(o.Body))},
		}, Text: strings.TrimSpace(strings.ReplaceAll(reqHeaders, "\r\n", "\n"))}}})

	br := bufio.NewReader(app)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirIn, Title: "HTTP response error", Warn: true, Note: err.Error()})
		return res, err
	}
	defer resp.Body.Close()
	tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirIn, Title: "HTTP response: " + resp.Status, Warn: resp.StatusCode >= 400,
		Sections: []trace.Section{respSection(resp, nil, -1)}})

	pv := &preview{}
	var sink io.Writer = pv
	if o.Output != nil {
		sink = io.MultiWriter(pv, o.Output)
	}
	n, err := io.Copy(sink, resp.Body)
	tr.PhaseEnd("Server processing") // empty body: no read after headers
	tr.PhaseEnd("Content download")
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirIn, Title: "HTTP body read failed", Warn: true, Note: err.Error()})
		return res, err
	}
	tr.Emit(trace.Event{Layer: trace.LayerHTTP, Dir: trace.DirIn, Title: fmt.Sprintf("HTTP body received: %d bytes", n),
		Sections: []trace.Section{respSection(resp, pv.buf.Bytes(), n)}})
	res.total = tr.Now()
	res.preview = pv.buf.Bytes()
	res.summary = append(res.summary, trace.Field{K: "Status", V: resp.Status}, trace.Field{K: "Body", V: fmt.Sprintf("%d bytes", n)})
	return res, nil
}

func respSection(resp *http.Response, body []byte, n int64) trace.Section {
	f := []trace.Field{
		{K: "Status line", V: resp.Proto + " " + resp.Status},
		{K: "Content-Type", V: orNone(resp.Header.Get("Content-Type"))},
	}
	if n >= 0 {
		f = append(f, trace.Field{K: "Body", V: fmt.Sprintf("%d bytes", n)})
	} else if resp.ContentLength >= 0 {
		f = append(f, trace.Field{K: "Content-Length", V: fmt.Sprint(resp.ContentLength)})
	} else if len(resp.TransferEncoding) > 0 {
		f = append(f, trace.Field{K: "Transfer-Encoding", V: strings.Join(resp.TransferEncoding, ", ")})
	}
	if s := resp.Header.Get("Server"); s != "" {
		f = append(f, trace.Field{K: "Server", V: s})
	}
	var lines []string
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			lines = append(lines, k+": "+v)
		}
	}
	text := strings.Join(lines, "\n")
	if len(body) > 0 {
		text += "\n\n" + printable(body)
	}
	return trace.Section{Layer: trace.LayerHTTP, Title: "Response", Fields: f, Text: text}
}

// printable returns a short text preview, or a note for binary bodies.
func printable(b []byte) string {
	if len(b) > 1024 {
		b = b[:1024]
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return fmt.Sprintf("(binary body, first bytes % x)", b[:min(len(b), 16)])
	}
	return string(b)
}

type preview struct{ buf bytes.Buffer }

func (p *preview) Write(b []byte) (int, error) {
	if room := previewLimit - p.buf.Len(); room > 0 {
		p.buf.Write(b[:min(room, len(b))])
	}
	return len(b), nil
}

// headCapture keeps the request head (up to the blank line).
type headCapture struct {
	buf  *bytes.Buffer
	done bool
}

func (h *headCapture) Write(b []byte) (int, error) {
	if !h.done {
		h.buf.Write(b)
		if i := bytes.Index(h.buf.Bytes(), []byte("\r\n\r\n")); i >= 0 {
			h.buf.Truncate(i)
			h.done = true
		}
	}
	return len(b), nil
}
