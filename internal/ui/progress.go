package ui

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type DockerProgress struct {
	w         io.Writer
	phase     string
	total     int
	current   int
	startTime time.Time
}

func NewProgressReporter(w io.Writer) *DockerProgress {
	return &DockerProgress{w: w}
}

func (p *DockerProgress) StartPhase(name string, total int) {
	p.phase = name
	p.total = total
	p.current = 0
	p.startTime = time.Now()
	// Clear line and print start
	fmt.Fprintf(p.w, "%s %s[%s]%s %sStarting %s...%s\n", 
		cyan, reset, time.Now().Format("15:04:05.000"), cyan, dim, name, reset)
}

func (p *DockerProgress) Update(current int) {
	p.current = current
	p.render()
}

func (p *DockerProgress) EndPhase() {
	p.render()
	fmt.Fprint(p.w, "\n")
}

func (p *DockerProgress) render() {
	percent := 0.0
	if p.total > 0 {
		percent = float64(p.current) / float64(p.total) * 100
	}

	elapsed := time.Since(p.startTime).Truncate(time.Second)
	
	// Progress bar
	width := 30
	completed := int(float64(width) * (percent / 100))
	if completed > width {
		completed = width
	}
	bar := strings.Repeat("=", completed)
	if completed < width {
		bar += ">" + strings.Repeat(" ", width-completed-1)
	}
	
	// Docker-like status line
	// \r to return to start of line, \033[K to clear to end of line
	fmt.Fprintf(p.w, "\r %s[%02d:%02d]%s [%s] %3.0f%% (%d/%d) %s%-20s%s\033[K",
		cyan, int(elapsed.Minutes()), int(elapsed.Seconds())%60, reset,
		bar, percent, p.current, p.total,
		dim, p.phase, reset)
}
