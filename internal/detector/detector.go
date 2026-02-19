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

// New creates a new Detector with the given patterns; If no patterns are provided, it uses DefaultPatterns.
func New(patterns []Pattern) *Detector {
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}
	return &Detector{patterns: patterns}
}

// Detect scans the provided content and returns a list of findings.
func (d *Detector) Detect(content []byte) ([]types.Finding, error) {
	lines := d.parseLines(content)
	findings := d.scanLines(lines)
	return findings, nil
}

func (d *Detector) parseLines(content []byte) []string {
	return strings.Split(string(content), "\n")
}

// scanLines checks all lines against all patterns.
// Returns accumulated findings from all matches.
func (d *Detector) scanLines(lines []string) []types.Finding {
	findings := make([]types.Finding, 0)

	for lineNum, line := range lines {
		lineFindings := d.scanLine(line, lineNum+1)
		findings = append(findings, lineFindings...)
	}

	return findings
}

// scanLine checks a single line against all patterns; Returns all matches found on this line.
func (d *Detector) scanLine(line string, lineNumber int) []types.Finding {
	findings := make([]types.Finding, 0, len(d.patterns))

	for i := range d.patterns {
		if finding, matched := d.checkPattern(&d.patterns[i], line, lineNumber); matched {
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkPattern tests if a pattern matches the line; Returns (finding, true) if matched, (empty, false) otherwise.
func (d *Detector) checkPattern(pattern *Pattern, line string, lineNumber int) (types.Finding, bool) {
	if !pattern.Regex.MatchString(line) {
		return types.Finding{}, false
	}

	finding := types.Finding{
		LineNumber: lineNumber,
		SecretType: pattern.Name,
		Value:      strings.TrimSpace(line),
	}

	return finding, true
}
