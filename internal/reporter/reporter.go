package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hadnu/cicd-secret-detector/internal/types"
)

// reportFinding is the safe, serializable representation of a Finding.
type reportFinding struct {
	FilePath      string `json:"file_path"`
	LineNumber    int    `json:"line_number"`
	SecretType    string `json:"secret_type"`
	RedactedValue string `json:"redacted_value"`
}

func toReportFindings(findings []types.Finding) []reportFinding {
	out := make([]reportFinding, len(findings))
	for i, f := range findings {
		out[i] = reportFinding{
			FilePath:      f.FilePath,
			LineNumber:    f.LineNumber,
			SecretType:    f.SecretType,
			RedactedValue: f.RedactedValue,
		}
	}
	return out
}

// Report writes findings to the writer in the specified format.
func Report(w io.Writer, findings []types.Finding, format string) error {
	switch format {
	case "json":
		return reportJSON(w, findings)
	default:
		return reportText(w, findings)
	}
}

func reportJSON(w io.Writer, findings []types.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func reportText(w io.Writer, findings []types.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No secrets found.")
		return nil
	}

	safe := toReportFindings(findings)

	fmt.Fprintf(w, "Found %d potential secrets:\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(w, "[%d] %s:%d\n", i+1, f.FilePath, f.LineNumber)
		fmt.Fprintf(w, "    Type: %s\n", f.SecretType)
		fmt.Fprintf(w, "    Match: %s\n\n", f.Value)
	}
	return nil
}
