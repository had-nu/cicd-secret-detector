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

var ignoreDirs = map[string]struct{} {
	".git":         {},
	".idea":        {},
	".vscode":      {},
	"vendor":       {},
	"node_modules": {},
	"bin":          {},
}

// FileScanner scans files for secrets.
type FileScanner struct {
	detector Detector
}

// New creates a new FileScanner.
func New(d Detector) *FileScanner {
	return &FileScanner {
		detector: d
	}
}

// Scan walks the root directory and scans files for secrets.
func (s *FileScanner) Scan(ctx context.Context, root string) ([]types.Finding, error) {
	var (
		findings []types.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	sem := make(chan struct{}, 100)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if shouldIgnoreDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if s.shouldIgnoreDir(d.Name()) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

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

	for i := range result {
		result[i].FilePath = path
	}

	return result, nil
}

func shouldIgnoreDir(name string) bool {
	_, ok := ignoreDirs[name]
	return ok
}
