package types

// Finding represents a detected secret in a file.
type Finding struct {
	FilePath   		string
	LineNumber 		int
	SecretType 		string
	Value      		string 		// Raw value — for internal processing only, never log or display
	RedactedValue 	string 	// Safe for output: preserves context, hides the secret
}

// Secret represents a definition of a secret to look for.
type Secret struct {
	Name    string
	Pattern string // Regex pattern
}
