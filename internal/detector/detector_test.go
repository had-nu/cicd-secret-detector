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

func TestDetector_CustomPatterns(t *testing.T) {
	// Correct way to test custom patterns
	importRegexp := func(s string) *regexp.Regexp {
		return regexp.MustCompile(s)
	}

	d := New([]Pattern{
		{Name: "Foo", Regex: importRegexp("foo")},
	})

	findings, _ := d.Detect([]byte("foo bar"))
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding for custom pattern, got %d", len(findings))
	}
}
