package ui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// Waterfall draws one bar per phase on a shared time axis. Open phases run
// up to now.
func Waterfall(phases []trace.Phase, now time.Duration, width int) string {
	if len(phases) == 0 {
		return dim.Render("  (no timings yet)")
	}
	const labelW, durW = 18, 10
	barW := width - labelW - durW - 3
	if barW < 10 {
		barW = 10
	}
	var total time.Duration
	for _, p := range phases {
		end := p.End
		if !p.Done {
			end = now
		}
		total = max(total, end)
	}
	if total <= 0 {
		total = 1
	}
	col := func(d time.Duration) int { return int(float64(d) / float64(total) * float64(barW)) }
	var b strings.Builder
	for _, p := range phases {
		end := p.End
		if !p.Done {
			end = now
		}
		s, e := col(p.Start), col(end)
		if e <= s {
			e = s + 1
		}
		if e > barW {
			e = barW
			s = min(s, e-1)
		}
		st := lipgloss.NewStyle().Foreground(phaseColor(p.Name))
		ch := "█"
		if !p.Done {
			ch = "▓"
		}
		bar := strings.Repeat(" ", s) + st.Render(strings.Repeat(ch, e-s)) + strings.Repeat(" ", barW-e)
		b.WriteString(pad(p.Name, labelW) + dim.Render("│") + bar + dim.Render("│") + " " + st.Render(fmtDur(end-p.Start)) + "\n")
	}
	axisEnd := fmtDur(total)
	b.WriteString(strings.Repeat(" ", labelW) + dim.Render("0"+strings.Repeat(" ", max(1, barW+1-len(axisEnd)))+axisEnd))
	return b.String()
}
