package types

import "fmt"

// Finding represents a detected secret in a file.
type Finding struct {
	FilePath             string
	LineNumber           int
	SecretType           string
	SecretClass          string  `json:"secret_class"`         // "token" | "credential"
	Value                string  `json:"-"`                   // Raw value — for internal processing only, never log or display
	ValueHash            string  `json:"value_hash"`
	RedactedValue        string                               // Safe for output: preserves context, hides the secret
	Entropy              float64
	StructuralValid      *bool   `json:"structural_valid,omitempty"` // nil when no validator
	Confidence           string
	ExposureContext      string
	RecencyTier          string
	DuplicateAcrossFiles bool
	// Phase B fields — zero values in v2.5.0, populated in v2.6.0:
	ComplianceControls   []string `json:"compliance_controls,omitempty"`
	BlastRadius          string   `json:"blast_radius,omitempty"`
	RemediationSteps     []string `json:"remediation_steps,omitempty"`
}

// ScanError records a file-level error encountered during scanning.
type ScanError struct {
	Path   string `json:"path"`
	ErrMsg string `json:"error"` // human-readable, safe to serialize
	Err    error  `json:"-"`     // original error for programmatic use
}

func NewScanError(path string, err error) ScanError {
	return ScanError{Path: path, ErrMsg: err.Error(), Err: err}
}

func (se ScanError) Error() string {
	return se.Path + ": " + se.Err.Error()
}

// TruncationError records that a file was larger than the scan limit
// and was read only partially. It is non-fatal: findings from the
// readable portion are still reported.
type TruncationError struct {
	Path  string
	Size  int64
	Limit int64
}

func (e *TruncationError) Error() string {
	return fmt.Sprintf("%s: file size %d exceeds scan limit %d, truncated", e.Path, e.Size, e.Limit)
}

// ScanResult is the structured return value of a scan.
type ScanResult struct {
	FilesScanned int
	Findings     []Finding
	Errors       []ScanError
	Truncated    bool // true quando ctx expirou antes do fim
}

// ConfidenceLevels provides a unified ordering for confidence scores.
var ConfidenceLevels = map[string]int{
	"Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}

// HasErrors reports whether any file-level errors were recorded.
func (r ScanResult) HasErrors() bool {
	return len(r.Errors) > 0
}

