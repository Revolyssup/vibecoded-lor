package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

type msgBatch []trace.Msg
type chanClosed struct{}
type tick time.Time

// Model is the Bubble Tea model of the live view.
type Model struct {
	src     <-chan trace.Msg
	start   time.Time
	TCPMode bool

	info    trace.Info
	events  []trace.Event
	phases  []trace.Phase
	Final   *trace.Done
	remote  string
	sel     int
	follow  bool
	detail  bool
	scroll  int
	w, h    int
	running bool
}

func NewModel(tr *trace.Tracer, tcpMode bool) *Model {
	return &Model{src: tr.C(), start: tr.Start(), TCPMode: tcpMode, follow: true, running: true, sel: -1, remote: "server"}
}

func (m *Model) Init() tea.Cmd { return tea.Batch(m.recv(), tickCmd()) }

func tickCmd() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg { return tick(t) })
}

// recv waits for the next message and drains whatever else is queued.
func (m *Model) recv() tea.Cmd {
	return func() tea.Msg {
		first, ok := <-m.src
		if !ok {
			return chanClosed{}
		}
		b := msgBatch{first}
		for len(b) < 256 {
			select {
			case x, ok := <-m.src:
				if !ok {
					return b
				}
				b = append(b, x)
			default:
				return b
			}
		}
		return b
	}
}

func (m *Model) apply(x trace.Msg) {
	switch v := x.(type) {
	case trace.Event:
		i := sort.Search(len(m.events), func(i int) bool { return m.events[i].At > v.At })
		m.events = append(m.events, trace.Event{})
		copy(m.events[i+1:], m.events[i:])
		m.events[i] = v
		if !m.follow && m.sel >= i {
			m.sel++
		}
		for _, s := range v.Sections {
			if s.Layer == trace.LayerIP {
				for _, f := range s.Fields {
					if f.K == "Destination" && v.Dir != trace.DirIn && !strings.HasPrefix(f.V, "(") {
						m.remote = f.V
					}
				}
			}
		}
	case trace.Phase:
		for i := range m.phases {
			if m.phases[i].Name == v.Name {
				m.phases[i] = v
				return
			}
		}
		m.phases = append(m.phases, v)
	case trace.Info:
		if v.Target != "" {
			m.info.Target = v.Target
		}
		if v.Capture != "" {
			m.info.Capture = v.Capture
		}
	case trace.Done:
		m.Final = &v
		m.running = false
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case msgBatch:
		for _, x := range v {
			m.apply(x)
		}
		if m.follow {
			m.sel = len(m.events) - 1
		}
		return m, m.recv()
	case chanClosed:
		m.running = false
		return m, nil
	case tick:
		if m.running {
			return m, tickCmd()
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.w, m.h = v.Width, v.Height
	case tea.KeyMsg:
		switch v.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			m.follow = false
			m.sel = max(0, m.sel-1)
			m.scroll = 0
		case "down", "j":
			m.sel = min(len(m.events)-1, m.sel+1)
			m.follow = m.sel == len(m.events)-1 && m.running
			m.scroll = 0
		case "home", "g":
			m.follow, m.sel, m.scroll = false, 0, 0
		case "end", "G", "f":
			m.follow, m.sel, m.scroll = true, len(m.events)-1, 0
		case "d":
			m.detail = !m.detail
		case "pgdown", "J", " ":
			m.scroll += 5
		case "pgup", "K":
			m.scroll = max(0, m.scroll-5)
		}
	}
	return m, nil
}

func (m *Model) View() string {
	if m.w == 0 {
		return ""
	}
	header := m.header()
	footer := dim.Render(" ↑/↓ step through events · g/G first/last · d detail · PgUp/PgDn scroll stack · q quit")
	bodyH := m.h - lipgloss.Height(header) - 1
	leftW := m.w * 52 / 100
	rightW := m.w - leftW - 1

	stack := renderStack(m.events, m.sel, leftW, m.detail, m.TCPMode, m.remote)
	m.scroll = min(m.scroll, max(0, len(stack)-bodyH))
	stack = stack[m.scroll:]
	left := clip(stack, bodyH, leftW)

	right := m.rightPane(rightW, bodyH)
	sep := dim.Render(strings.TrimRight(strings.Repeat("│\n", bodyH), "\n"))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, sep, right)
	return header + "\n" + body + "\n" + footer
}

func (m *Model) header() string {
	badge := lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Bold(true).Padding(0, 1).Render("lor")
	status := lipgloss.NewStyle().Foreground(lipgloss.Color("221")).Render("● running " + fmtDur(time.Since(m.start)))
	if m.Final != nil {
		if m.Final.Err != nil {
			status = warn.Render("✗ " + m.Final.Err.Error())
		} else {
			parts := []string{}
			for _, f := range m.Final.Summary {
				if f.K == "Status" || f.K == "Total time" || f.K == "Received" {
					parts = append(parts, f.V)
				}
			}
			status = lipgloss.NewStyle().Foreground(colTCP).Render("✓ done " + strings.Join(parts, " · "))
		}
	}
	capture := m.info.Capture
	if capture == "" {
		capture = "…"
	}
	line := badge + " " + bold.Render(m.info.Target) + "  " + status
	return trunc(line, m.w) + "\n" + trunc(dim.Render(" mode: "+capture), m.w)
}

func (m *Model) rightPane(w, h int) string {
	wf := Waterfall(m.phases, time.Since(m.start), w)
	wfLines := strings.Split(wf, "\n")
	wfH := len(wfLines) + 2
	listH := max(3, h-wfH)

	var lines []string
	lines = append(lines, bold.Render(fmt.Sprintf("What's happening on the wire (%d events)", len(m.events))))
	rows := listH - 1
	first := 0
	if m.sel >= rows {
		first = m.sel - rows + 1
	}
	for i := first; i < len(m.events) && i < first+rows; i++ {
		lines = append(lines, m.eventLine(i, w))
	}
	for len(lines) < listH {
		lines = append(lines, "")
	}
	lines = append(lines, "", bold.Render("Timing waterfall"))
	lines = append(lines, wfLines...)
	return clip(lines, h, w)
}

func (m *Model) eventLine(i, w int) string {
	e := m.events[i]
	ts := fmt.Sprintf("%10s", "+"+fmtDur(e.At))
	if i == m.sel {
		plain := "▶" + ts[1:] + " " + e.Dir.Arrow() + " " + pad(e.Layer.String(), 4) + " " + clean(e.Title)
		return lipgloss.NewStyle().Background(colSel).Foreground(lipgloss.Color("231")).Bold(true).Render(pad(plain, w))
	}
	tag := lipgloss.NewStyle().Foreground(layerColor(e.Layer)).Render(pad(e.Layer.String(), 4))
	ttl := lipgloss.NewStyle()
	switch {
	case e.Warn:
		ttl = warn
	case strings.Contains(e.Title, "(inferred)"):
		ttl = faint.Italic(true)
	}
	return pad(dim.Render(ts)+" "+e.Dir.Arrow()+" "+tag+" "+ttl.Render(clean(e.Title)), w)
}

func clip(lines []string, h, w int) string {
	if len(lines) > h {
		lines = lines[:h]
	}
	for i := range lines {
		lines[i] = pad(lines[i], w)
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

// Phases returns the timing phases collected so far.
func (m *Model) Phases() []trace.Phase { return m.phases }
