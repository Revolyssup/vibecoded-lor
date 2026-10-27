// Command lor sends an HTTP or TCP request and shows, layer by layer, what
// happens on the wire while it runs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"

	"github.com/revolyssup/vibecoded-lor/internal/capture"
	"github.com/revolyssup/vibecoded-lor/internal/probe"
	"github.com/revolyssup/vibecoded-lor/internal/trace"
	"github.com/revolyssup/vibecoded-lor/internal/ui"
)

const version = "0.1.0"

const usage = `lor - see your request travel down and up the TCP/IP stack

Usage:
  lor [flags] <url>                 HTTP/1.1 request (http:// or https://)
  lor tcp [flags] <host:port>       raw TCP (or --tls) exchange
  lor version

Examples:
  lor https://example.com
  lor -X POST -H 'Content-Type: application/json' -d '{"a":1}' https://httpbin.org/post
  sudo lor https://example.com      real packets (needs root / CAP_NET_RAW on Linux)
  lor tcp -d 'PING\r\n' localhost:6379
  lor tcp --tls -d 'HEAD / HTTP/1.0\r\n\r\n' example.com:443

Flags:
`

type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

type common struct {
	data      string
	insecure  bool
	output    string
	timeout   time.Duration
	plain     bool
	verbose   bool
	noCapture bool
	iface     string
	ipv4      bool
	ipv6      bool
	resolve   string
	keylog    string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.data, "d", "", "data to send; @file reads a file, @- reads stdin")
	fs.BoolVar(&c.insecure, "k", false, "skip TLS certificate verification")
	fs.StringVar(&c.output, "o", "", "write the response body to this file")
	fs.DurationVar(&c.timeout, "timeout", 30*time.Second, "overall timeout")
	fs.BoolVar(&c.plain, "plain", false, "no TUI: print events as text (default when stdout is not a terminal)")
	fs.BoolVar(&c.verbose, "v", false, "with --plain, print every layer's fields for each event")
	fs.BoolVar(&c.noCapture, "no-capture", false, "don't capture packets, use socket-level info only")
	fs.StringVar(&c.iface, "iface", "", "interface to capture on (default: the one routing to the server)")
	fs.BoolVar(&c.ipv4, "4", false, "use IPv4 only")
	fs.BoolVar(&c.ipv6, "6", false, "use IPv6 only")
	fs.StringVar(&c.resolve, "resolve", "", "connect to this IP instead of resolving the host")
	fs.StringVar(&c.keylog, "keylog", os.Getenv("SSLKEYLOGFILE"), "append TLS secrets to this file (for Wireshark)")
}

func (c *common) dial() probe.DialOptions {
	fam := ""
	if c.ipv4 {
		fam = "4"
	} else if c.ipv6 {
		fam = "6"
	}
	return probe.DialOptions{Family: fam, Resolve: c.resolve, Timeout: c.timeout}
}

// parse lets flags appear before and after the positional argument, like curl.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func readData(s string, unescape bool) ([]byte, error) {
	switch {
	case s == "@-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(s, "@"):
		return os.ReadFile(s[1:])
	case unescape:
		r := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t", `\0`, "\x00", `\\`, `\`)
		return []byte(r.Replace(s)), nil
	}
	return []byte(s), nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lor:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Println("lor", version)
			return nil
		case "tcp":
			return runTCP(args[1:])
		}
	}
	return runHTTP(args)
}

func newFlagSet(name, extra string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage+extra)
		fs.PrintDefaults()
	}
	return fs
}

func runHTTP(args []string) error {
	var c common
	var headers headerList
	fs := newFlagSet("lor", "")
	c.register(fs)
	method := fs.String("X", "", "request method (default GET, or POST with -d)")
	fs.Var(&headers, "H", "extra header 'Name: value' (repeatable)")
	pos, err := parse(fs, args)
	if err == flag.ErrHelp {
		return nil
	} else if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one URL")
	}
	url := pos[0]
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	o := probe.HTTPOptions{Method: *method, URL: url, Headers: headers, Insecure: c.insecure, Dial: c.dial(), Timeout: c.timeout}
	if c.data != "" {
		if o.Body, err = readData(c.data, false); err != nil {
			return err
		}
	}
	if o.Method == "" {
		o.Method = "GET"
		if o.Body != nil {
			o.Method = "POST"
		}
	}
	return execute(&c, false, func(tr *trace.Tracer, cp *capture.Capturer, out, kl io.Writer) {
		o.Output, o.KeyLog, o.Dial.Capture = out, kl, cp
		probe.RunHTTP(tr, o)
	})
}

func runTCP(args []string) error {
	var c common
	fs := newFlagSet("lor tcp", "")
	c.register(fs)
	useTLS := fs.Bool("tls", false, "wrap the connection in TLS")
	sni := fs.String("sni", "", "TLS server name (default: the host)")
	idle := fs.Duration("read-timeout", 2*time.Second, "stop reading after this much silence")
	pos, err := parse(fs, args)
	if err == flag.ErrHelp {
		return nil
	} else if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one host:port")
	}
	o := probe.TCPOptions{Addr: pos[0], TLS: *useTLS, ServerName: *sni, Insecure: c.insecure, ReadTimeout: *idle, Dial: c.dial(), Timeout: c.timeout}
	if c.data != "" {
		if o.Data, err = readData(c.data, true); err != nil {
			return err
		}
	}
	return execute(&c, true, func(tr *trace.Tracer, cp *capture.Capturer, out, kl io.Writer) {
		o.Output, o.KeyLog, o.Dial.Capture = out, kl, cp
		probe.RunTCP(tr, o)
	})
}

func execute(c *common, tcpMode bool, start func(tr *trace.Tracer, cp *capture.Capturer, out, keylog io.Writer)) error {
	tui := !c.plain && term.IsTerminal(os.Stdout.Fd()) && term.IsTerminal(os.Stdin.Fd())
	var out io.Writer
	if c.output != "" {
		f, err := os.Create(c.output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	} else if !tui {
		out = os.Stdout
	}
	var kl io.Writer
	if c.keylog != "" {
		f, err := os.OpenFile(c.keylog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		kl = f
	}
	width := 100
	if w, _, err := term.GetSize(os.Stderr.Fd()); err == nil && w > 0 {
		width = w
	}

	// Capture is opened before the clock starts so its setup cost is not
	// part of the timings.
	cp, err := capture.Open(capture.Options{Disabled: c.noCapture, Iface: c.iface})
	tr := trace.New()
	if err != nil {
		tr.SetInfo(trace.Info{Capture: "socket-level only (" + err.Error() + ")"})
		if !c.noCapture {
			tr.Emit(trace.Event{Title: "No packet capture: " + err.Error(),
				Note: "Handshake packets are inferred from the socket. Run as root (or grant CAP_NET_RAW) to see real packets."})
		}
	} else {
		tr.SetInfo(trace.Info{Capture: cp.Describe()})
		defer cp.Stop()
	}
	go start(tr, cp, out, kl)

	if !tui {
		done := ui.RunPlain(tr, os.Stderr, c.verbose, width)
		if done.Err != nil {
			os.Exit(1)
		}
		return nil
	}
	m := ui.NewModel(tr, tcpMode)
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return err
	}
	if m.Final == nil {
		fmt.Fprintln(os.Stderr, "lor: interrupted")
		return nil
	}
	ui.PrintReport(os.Stdout, m.Phases(), *m.Final, width)
	if m.Final.Err != nil {
		os.Exit(1)
	}
	return nil
}
