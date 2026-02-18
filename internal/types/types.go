package types

// Finding represents a detected secret in a file.
type Finding struct {
	FilePath   string
	LineNumber int
	SecretType string
	Value      string // Redacted or raw value? usually redacted in logs, raw in internal processing
}

// Secret represents a definition of a secret to look for.
type Secret struct {
	Name    string
	Pattern string // Regex pattern
}
