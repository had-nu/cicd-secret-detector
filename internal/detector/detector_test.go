package detector

import (
	"regexp"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int // number of findings
	}{
		{
			name:    "AWS Access Key",
			content: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			want:    1,
		},
		{
			name:    "AWS Secret Key",
			content: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:    1,
		},
		{
			name:    "Private Key",
			content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA3T...",
			want:    1,
		},
		{
			name:    "Generic API Key",
			content: "api_key: \"1234567890abcdef1234567890abcdef\"",
			want:    1,
		},
		{
			name:    "No Secrets",
			content: "# This is a config file\nfoo: bar",
			want:    0,
		},
	}

	d := New(nil) // Use default patterns

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Errorf("Detect() error = %v", err)
				return
			}
			if len(got) != tt.want {
				t.Errorf("Detect() = %d findings, want %d", len(got), tt.want)
			}
			if len(got) > 0 {
				// Basic check to ensure finding has data
				if got[0].SecretType == "" {
					t.Error("Finding.SecretType is empty")
				}
				if got[0].LineNumber == 0 {
					t.Error("Finding.LineNumber is 0")
				}
			}
		})
	}
}

func TestRedactedValue(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		wantNotContain  string // raw secret must NOT appear in RedactedValue
		wantContain     string // context key MUST appear in RedactedValue
	}{
		{
			name:           "AWS Secret Key redacts value but keeps key name",
			content:        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantNotContain: "wJalrXUtnFEMI",
			wantContain:    "aws_secret_access_key",
		},
		{
			name:           "Generic API Key redacts value but keeps key name",
			content:        "api_key = abcdef1234567890abcdef1234567890",
			wantNotContain: "abcdef1234567890",
			wantContain:    "api_key",
		},
		{
			name:           "AWS Access Key ID is fully redacted",
			content:        "AKIAIOSFODNN7EXAMPLE",
			wantNotContain: "AKIAIOSFODNN7EXAMPLE",
			wantContain:    "[REDACTED]",
		},
		{
			name:           "Private Key header is fully redacted",
			content:        "-----BEGIN RSA PRIVATE KEY-----",
			wantNotContain: "BEGIN RSA PRIVATE KEY",
			wantContain:    "[REDACTED]",
		},
	}

	d := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := d.Detect([]byte(tt.content))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected at least one finding, got none")
			}

			rv := findings[0].RedactedValue

			if strings.Contains(rv, tt.wantNotContain) {
				t.Errorf("RedactedValue contains raw secret %q — must not appear in output\nRedactedValue: %s", tt.wantNotContain, rv)
			}
			if !strings.Contains(rv, tt.wantContain) {
				t.Errorf("RedactedValue missing expected context %q\nRedactedValue: %s", tt.wantContain, rv)
			}

			// Raw value must always be present in Value (for internal processing)
			if findings[0].Value == "" {
				t.Error("Finding.Value must not be empty — required for internal processing")
			}
		})
	}
}

func TestRedactedValue_NeverEmpty(t *testing.T) {
	// Any finding must always have a non-empty RedactedValue.
	// An empty RedactedValue would silently suppress output context.
	d := New(nil)

	inputs := []string{
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----",
		"api_key: abcdef1234567890abcdef12",
	}

	for _, input := range inputs {
		findings, _ := d.Detect([]byte(input))
		for _, f := range findings {
			if f.RedactedValue == "" {
				t.Errorf("Finding.RedactedValue is empty for input: %q", input)
			}
		}
	}
}


func TestDetector_CustomPatterns(t *testing.T) {
	d := New([]Pattern{
		{
			Name:  "Foo",
			Regex: regexp.MustCompile("foo"),
			Redact: func(match string) string {
				return "[REDACTED]"
			},
		},
	})

	findings, _ := d.Detect([]byte("foo bar"))
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding for custom pattern, got %d", len(findings))
	}
	if findings[0].RedactedValue != "[REDACTED]" {
		t.Errorf("Expected [REDACTED], got %q", findings[0].RedactedValue)
	}
}
