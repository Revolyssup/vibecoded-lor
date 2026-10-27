package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// RunPlain prints events as they arrive (curl -v style) and the waterfall at
// the end. It returns the final Done message.
func RunPlain(tr *trace.Tracer, w io.Writer, verbose bool, width int) trace.Done {
	var phases []trace.Phase
	var done trace.Done
	for x := range tr.C() {
		switch v := x.(type) {
		case trace.Info:
			if v.Target != "" {
				fmt.Fprintln(w, bold.Render("lor "+v.Target))
			}
			if v.Capture != "" {
				fmt.Fprintln(w, dim.Render("mode: "+v.Capture))
			}
		case trace.Event:
			printEvent(w, v, verbose)
		case trace.Phase:
			found := false
			for i := range phases {
				if phases[i].Name == v.Name {
					phases[i], found = v, true
				}
			}
			if !found {
				phases = append(phases, v)
			}
		case trace.Done:
			done = v
		}
	}
	PrintReport(w, phases, done, width)
	return done
}

func printEvent(w io.Writer, e trace.Event, verbose bool) {
	tag := lipgloss.NewStyle().Foreground(layerColor(e.Layer)).Render(pad(e.Layer.String(), 4))
	title := clean(e.Title)
	if e.Warn {
		title = warn.Render(title)
	}
	fmt.Fprintf(w, "%s %s %s %s\n", dim.Render(fmt.Sprintf("%10s", "+"+fmtDur(e.At))), e.Dir.Arrow(), tag, title)
	if e.Note != "" {
		fmt.Fprintln(w, faint.Render("                  "+e.Note))
	}
	if !verbose {
		return
	}
	for _, s := range e.Sections {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(layerColor(s.Layer)).Render("                  ["+s.Layer.String()+"] "+s.Title))
		for _, f := range append(s.Fields[:len(s.Fields):len(s.Fields)], s.Detail...) {
			fmt.Fprintf(w, "                    %s %s\n", faint.Render(pad(f.K+":", 20)), clean(f.V))
		}
		if s.Text != "" {
			for _, l := range strings.Split(strings.ReplaceAll(s.Text, "\r\n", "\n"), "\n") {
				fmt.Fprintln(w, faint.Render("                    | "+clean(l)))
			}
		}
	}
}

// PrintReport prints the summary and timing waterfall.
func PrintReport(w io.Writer, phases []trace.Phase, done trace.Done, width int) {
	fmt.Fprintln(w)
	if done.Err != nil {
		fmt.Fprintln(w, warn.Render("error: "+done.Err.Error()))
	}
	for _, f := range done.Summary {
		fmt.Fprintf(w, "%s %s\n", faint.Render(pad(f.K+":", 14)), f.V)
	}
	if len(phases) > 0 {
		var end = phases[0].End
		for _, p := range phases {
			end = max(end, p.End)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, Waterfall(phases, end, min(width, 100)))
	}
}
