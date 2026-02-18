package detector

import (
	"regexp"
	"strings"

	"github.com/hadnu/cicd-secret-detector/internal/types"
)

// Pattern defines a regex for a specific secret type.
type Pattern struct {
	Name  string
	Regex *regexp.Regexp
}

// DefaultPatterns returns a list of common secret patterns.
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:  "AWS Access Key ID",
			Regex: regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		},
		{
			Name:  "AWS Secret Access Key",
			Regex: regexp.MustCompile(`(?i)aws_secret_access_key['"]?\s*(=|:)\s*['"]?[A-Za-z0-9\/+=]{40}['"]?`),
		},
		{
			Name:  "Private Key",
			Regex: regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
		},
		{
			Name:  "Generic API Key",
			Regex: regexp.MustCompile(`(?i)(api_key|apikey|secret|token)['"]?\s*(=|:)\s*['"]?[a-zA-Z0-9]{16,64}['"]?`),
		},
	}
}

// Detector scans content for secrets using defined patterns.
type Detector struct {
	patterns []Pattern
}

// New creates a new Detector with the given patterns.
// If no patterns are provided, it uses DefaultPatterns.
func New(patterns []Pattern) *Detector {
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}
	return &Detector{patterns: patterns}
}

// Detect scans the provided content and returns a list of findings.
func (d *Detector) Detect(content []byte) ([]types.Finding, error) {
	var findings []types.Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, p := range d.patterns {
			if p.Regex.MatchString(line) {
				findings = append(findings, types.Finding{
					// FilePath is not known here, allows reuse. Caller sets it.
					LineNumber: i + 1,
					SecretType: p.Name,
					Value:      strings.TrimSpace(line), // Store the matching line for now
				})
			}
		}
	}

	return findings, nil
}
