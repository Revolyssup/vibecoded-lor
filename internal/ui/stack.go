package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// stackLayer is one box of the textbook TCP/IP stack.
type stackLayer struct {
	label  string
	layers []trace.Layer // event layers shown in this box
	color  lipgloss.Color
}

func stackLayers(tcpMode bool) []stackLayer {
	app := stackLayer{"L7 Application · HTTP / DNS", []trace.Layer{trace.LayerHTTP, trace.LayerDNS}, colHTTP}
	if tcpMode {
		app = stackLayer{"L7 Application · your bytes / DNS", []trace.Layer{trace.LayerApp, trace.LayerDNS}, colApp}
	}
	return []stackLayer{
		app,
		{"L6 Security · TLS", []trace.Layer{trace.LayerTLS}, colTLS},
		{"L4 Transport · TCP", []trace.Layer{trace.LayerTCP}, colTCP},
		{"L3 Network · IP", []trace.Layer{trace.LayerIP}, colIP},
	}
}

func sectionsFor(e trace.Event, ls []trace.Layer) []trace.Section {
	var out []trace.Section
	for _, s := range e.Sections {
		for _, l := range ls {
			if s.Layer == l {
				out = append(out, s)
			}
		}
	}
	return out
}

// renderStack draws the stack as it looked at event sel: each box holds the
// most recent data seen for that layer, and boxes the event touched light up.
func renderStack(events []trace.Event, sel int, width int, detail, tcpMode bool, remote string) []string {
	var lines []string
	if sel < 0 || sel >= len(events) {
		lines = append(lines, dim.Render("Waiting for the first event…"))
		return lines
	}
	cur := events[sel]
	src := "socket"
	if cur.Source == trace.SrcWire {
		src = "wire"
	}
	head := fmt.Sprintf("+%s %s %s", fmtDur(cur.At), cur.Dir.Arrow(), clean(cur.Title))
	hs := bold
	if cur.Warn {
		hs = warn.Bold(true)
	}
	lines = append(lines, trunc(hs.Render(head)+dim.Render("  ["+src+"]"), width))
	if cur.Note != "" {
		for _, l := range wrap(clean(cur.Note), width-2) {
			lines = append(lines, faint.Render("  "+l))
		}
	}

	inner := width - 4
	for i, sl := range stackLayers(tcpMode) {
		var secs []trace.Section
		active := false
		for j := sel; j >= 0; j-- {
			if s := sectionsFor(events[j], sl.layers); len(s) > 0 {
				secs, active = s, j == sel
				break
			}
		}
		if i > 0 {
			lines = append(lines, connector(cur.Dir, active || touches(cur, stackLayers(tcpMode)[i-1]), width))
		}
		var body []string
		title := lipgloss.NewStyle().Foreground(sl.color).Bold(true).Render(sl.label)
		body = append(body, title)
		if len(secs) == 0 {
			body = append(body, dim.Render("· not used yet"))
		}
		for si, s := range secs {
			if len(secs) > 1 || active {
				body = append(body, lipgloss.NewStyle().Foreground(sl.color).Render("▸ "+s.Title))
			}
			fields := s.Fields
			if detail {
				fields = append(fields[:len(fields):len(fields)], s.Detail...)
			}
			limit := len(fields)
			if !active && !detail {
				limit = min(limit, 4)
			}
			for _, f := range fields[:limit] {
				body = append(body, fieldLine(f, inner, active))
			}
			if s.Text != "" && (active || detail) {
				tl := strings.Split(strings.ReplaceAll(s.Text, "\r\n", "\n"), "\n")
				max := 8
				if detail {
					max = 40
				}
				for k, t := range tl {
					if k == max {
						body = append(body, dim.Render(fmt.Sprintf("  … %d more lines (d for detail)", len(tl)-max)))
						break
					}
					body = append(body, dim.Render("  ")+faint.Render(trunc(clean(t), inner-2)))
				}
			}
			if !active && !detail && si == 0 && len(secs) > 1 {
				break
			}
		}
		border := colDim
		bs := lipgloss.RoundedBorder()
		if active {
			border = sl.color
			bs = lipgloss.ThickBorder()
		}
		box := lipgloss.NewStyle().Border(bs).BorderForeground(border).Padding(0, 1).Width(width - 2).
			Render(strings.Join(body, "\n"))
		lines = append(lines, strings.Split(box, "\n")...)
	}
	wire := fmt.Sprintf(" physical link ⇄ %s ", remote)
	side := max(0, (width-lipgloss.Width(wire))/2)
	lines = append(lines, dim.Render(strings.Repeat("═", side)+wire+strings.Repeat("═", max(0, width-side-lipgloss.Width(wire)))))
	return lines
}

func touches(e trace.Event, sl stackLayer) bool { return len(sectionsFor(e, sl.layers)) > 0 }

// connector draws the arrow between two boxes: data moves down the stack
// when sending (encapsulation) and up when receiving.
func connector(d trace.Dir, lit bool, width int) string {
	var s string
	switch d {
	case trace.DirOut:
		s = "▼ encapsulate"
	case trace.DirIn:
		s = "▲ decapsulate"
	default:
		s = "│"
	}
	st := dim
	if lit && d != trace.DirNone {
		st = bold
	}
	return st.Render(strings.Repeat(" ", width/2-1) + s)
}

func fieldLine(f trace.Field, w int, active bool) string {
	const kw = 17
	k := pad(f.K, kw)
	vs := lipgloss.NewStyle().Foreground(colTitle)
	if !active {
		vs = faint
	}
	return faint.Render(k) + vs.Render(trunc(clean(f.V), w-kw))
}

func wrap(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	for len(s) > w {
		i := strings.LastIndex(s[:w], " ")
		if i <= 0 {
			i = w
		}
		out = append(out, s[:i])
		s = strings.TrimLeft(s[i:], " ")
	}
	return append(out, s)
}
