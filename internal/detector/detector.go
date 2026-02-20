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
	Redact func(match string) string
}

func redactValue(match string) string {
	for i, ch := range match {
		if ch == '=' || ch == ':' {
			return strings.TrimSpace(match[:i+1]) + " [REDACTED]"
		}
	}
	return "[REDACTED]"
}

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

type Detector struct {
	patterns []Pattern
}

func New(patterns []Pattern) *Detector {
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}
	return &Detector{patterns: patterns}
}

func (d *Detector) Detect(content []byte) ([]types.Finding, error) {
	lines := d.parseLines(content)
	findings := d.scanLines(lines)
	return findings, nil
}

func (d *Detector) parseLines(content []byte) []string {
	return strings.Split(string(content), "\n")
}

func (d *Detector) scanLines(lines []string) []types.Finding {
	findings := make([]types.Finding, 0)

	for lineNum, line := range lines {
		lineFindings := d.scanLine(line, lineNum+1)
		findings = append(findings, lineFindings...)
	}

	return findings
}

func (d *Detector) scanLine(line string, lineNumber int) []types.Finding {
	findings := make([]types.Finding, 0, len(d.patterns))

	for i := range d.patterns {
		if finding, matched := d.checkPattern(&d.patterns[i], line, lineNumber); matched {
			findings = append(findings, finding)
		}
	}

	return findings
}

// Returns (finding, true) if matched, (empty, false) otherwise.
func (d *Detector) checkPattern(pattern *Pattern, line string, lineNumber int) (types.Finding, bool) {
	if !pattern.Regex.MatchString(line) {
		return types.Finding{}, false
	}

	redacted := "[REDACTED]"
	if pattern.Redact != nil {
		redacted = pattern.Redact(match)
	}

	finding := types.Finding{
		LineNumber:    lineNumber,
		SecretType:    pattern.Name,
		Value:         strings.TrimSpace(line), // raw: internal use only
		RedactedValue: redacted,
	}

	return finding, true
}
