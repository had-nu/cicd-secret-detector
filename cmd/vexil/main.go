package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/had-nu/vexil/internal/detector"
	"github.com/had-nu/vexil/internal/gitscanner"
	"github.com/had-nu/vexil/internal/reporter"
	"github.com/had-nu/vexil/internal/scanner"
	"github.com/had-nu/vexil/internal/types"
	"github.com/had-nu/vexil/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dirArg   = flag.String("dir", ".", "Directory to scan")
		format   = flag.String("format", "text", "Output format (text, json, sarif)")
		exclude  = flag.String("exclude", "", "Comma-separated list of directories to exclude")
		gitAware = flag.Bool("git-aware", false, "Scan the entire git history (log -p) instead of the working tree")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Parse excludes
	var excludes []string
	if *exclude != "" {
		excludes = strings.Split(*exclude, ",")
	}

	// Initialize components
	d := detector.New(nil) // Use defaults
	s := scanner.New(d, excludes)

	if *format == "text" {
		ui.PrintBanner(os.Stderr)
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", *dirArg)
	}

	// Scan
	start := time.Now()
	var result types.ScanResult
	
	if *gitAware {
		gs := gitscanner.New(d, *dirArg)
		if gs.IsShallowClone() {
			fmt.Fprintf(os.Stderr, "warning: shallow clone detected — git history scan is incomplete\n")
		}
		
		findings, err := gs.ScanHistory(ctx)
		if err != nil {
			return fmt.Errorf("git history scan: %w", err)
		}
		result.Findings = findings
		// Note: we don't count files for git stream, just the total findings
	} else {
		res, err := s.Scan(ctx, *dirArg)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		result = res
	}
	duration := time.Since(start)
	
	// Print summary exclusively in text mode. Wait, actually we shouldn't ruin JSON stream
	if *format == "text" {
		if *gitAware {
			fmt.Fprintf(os.Stderr, "Scanned git history in %v. Found %d secrets.\n", duration, len(result.Findings))
		} else {
			fmt.Fprintf(os.Stderr, "Scanned %d files in %v. Found %d secrets.\n", result.FilesScanned, duration, len(result.Findings))
		}
	}

	// Report any file-level errors so they are visible to the operator.
	for _, se := range result.Errors {
		fmt.Fprintf(os.Stderr, "warning: %s\n", se)
	}

	// Report
	if err := reporter.Report(os.Stdout, result, *format); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	if len(result.Findings) > 0 {
		return fmt.Errorf("secrets found")
	}

	return nil
}
