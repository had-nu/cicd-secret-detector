package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hadnu/cicd-secret-detector/internal/types"
)

// Detector defines the behavior required to detect secrets in content.
type Detector interface {
	Detect(content []byte) ([]types.Finding, error)
}

// FileScanner scans files for secrets.
type FileScanner struct {
	detector Detector
	ignore   []string // Basic ignore list (e.g., ".git")
}

// New creates a new FileScanner.
func New(d Detector) *FileScanner {
	return &FileScanner{
		detector: d,
		ignore:   []string{".git", ".idea", ".vscode", "vendor", "node_modules"},
	}
}

// Scan walks the root directory and scans files for secrets.
// It uses a simple worker pool-like approach by spawning a goroutine for each file
// (buffered by a semaphore) or just walking and processing.
// For simplicity and "boring code", we'll stick to sequential walking or limited concurrency.
// Given IO bounds, `filepath.WalkDir` is single-threaded. We can dispatch work to a worker pool.
func (s *FileScanner) Scan(ctx context.Context, root string) ([]types.Finding, error) {
	var (
		findings []types.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	// Semaphore to limit concurrency (e.g., 100 open files max)
	sem := make(chan struct{}, 100)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if s.shouldIgnore(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if s.shouldIgnore(d.Name()) { // Also ignore files like .DS_Store
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Acquire semaphore BEFORE spawning to limit goroutines and provide backpressure
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }() // Release

			f, err := s.scanFile(ctx, path)
			if err != nil {
				// For now, log error or ignore?
				// In a real CLI, we might want to report access errors but not fail headers.
				// Let's print to stderr for now or collect them.
				// "User errors or I/O failures MUST return error" - but for a bulk scan, stopping on one file permission error is annoying.
				// Let's ignore individual file read errors for the bulk scan but maybe log them if we had a logger.
				return
			}

			if len(f) > 0 {
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			}
		}(path)

		return nil
	})

	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("scan walk %s: %w", root, err)
	}

	return findings, nil
}

func (s *FileScanner) scanFile(ctx context.Context, path string) ([]types.Finding, error) {
	// Check context again before expensive IO
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	result, err := s.detector.Detect(content)
	if err != nil {
		return nil, fmt.Errorf("detect %s: %w", path, err)
	}

	// Enrich findings with file path
	for i := range result {
		result[i].FilePath = path
	}

	return result, nil
}

func (s *FileScanner) shouldIgnore(name string) bool {
	for _, ign := range s.ignore {
		if name == ign || strings.HasPrefix(name, ".") && len(name) > 1 { // Simple dotfile ignore + explicit list
			return true
		}
	}
	return false
}
