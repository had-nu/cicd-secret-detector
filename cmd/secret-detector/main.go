package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/hadnu/cicd-secret-detector/internal/detector"
	"github.com/hadnu/cicd-secret-detector/internal/reporter"
	"github.com/hadnu/cicd-secret-detector/internal/scanner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dirArg = flag.String("dir", ".", "Directory to scan")
		format = flag.String("format", "text", "Output format (text, json)")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Initialize components
	d := detector.New(nil) // Use defaults
	s := scanner.New(d)

	// Scan
	fmt.Fprintf(os.Stderr, "Scanning %s...\n", *dirArg)
	start := time.Now()
	findings, err := s.Scan(ctx, *dirArg)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	duration := time.Since(start)
	fmt.Fprintf(os.Stderr, "Scanned in %v. Found %d secrets.\n", duration, len(findings))

	// Report
	if err := reporter.Report(os.Stdout, findings, *format); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	if len(findings) > 0 {
		return fmt.Errorf("secrets found")
	}

	return nil
}
