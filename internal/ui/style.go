// Package ui renders a trace as a live two-pane TUI or as plain text.
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

var (
	colDNS   = lipgloss.Color("37")
	colIP    = lipgloss.Color("33")
	colTCP   = lipgloss.Color("42")
	colTLS   = lipgloss.Color("170")
	colHTTP  = lipgloss.Color("214")
	colApp   = lipgloss.Color("180")
	colInfo  = lipgloss.Color("245")
	colDim   = lipgloss.Color("240")
	colWarn  = lipgloss.Color("203")
	colSel   = lipgloss.Color("237")
	colTitle = lipgloss.Color("230")

	dim   = lipgloss.NewStyle().Foreground(colDim)
	faint = lipgloss.NewStyle().Foreground(colInfo)
	warn  = lipgloss.NewStyle().Foreground(colWarn)
	bold  = lipgloss.NewStyle().Bold(true)
)

func layerColor(l trace.Layer) lipgloss.Color {
	switch l {
	case trace.LayerDNS:
		return colDNS
	case trace.LayerIP:
		return colIP
	case trace.LayerTCP:
		return colTCP
	case trace.LayerTLS:
		return colTLS
	case trace.LayerHTTP:
		return colHTTP
	case trace.LayerApp:
		return colApp
	}
	return colInfo
}

func phaseColor(name string) lipgloss.Color {
	switch {
	case strings.HasPrefix(name, "DNS"):
		return colDNS
	case strings.HasPrefix(name, "TCP"):
		return colTCP
	case strings.HasPrefix(name, "TLS"):
		return colTLS
	case strings.HasPrefix(name, "Request"), strings.HasPrefix(name, "Send"):
		return colHTTP
	case strings.HasPrefix(name, "Server"), strings.HasPrefix(name, "Waiting"):
		return lipgloss.Color("221")
	case strings.HasPrefix(name, "Content"), strings.HasPrefix(name, "Receive"):
		return lipgloss.Color("75")
	}
	return colInfo
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.3fs", d.Seconds())
}

func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	return ansi.Truncate(s, w, "…")
}

func pad(s string, w int) string {
	if n := ansi.StringWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return trunc(s, w)
}

// clean makes untrusted text (payloads, headers) safe to draw: carriage
// returns and other control characters would corrupt the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r < 32 || r == 127 || (r >= 0x80 && r < 0xa0):
			return '·'
		}
		return r
	}, s)
}
