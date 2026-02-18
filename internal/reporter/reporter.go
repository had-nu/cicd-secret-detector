package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hadnu/cicd-secret-detector/internal/types"
)

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

	fmt.Fprintf(w, "Found %d potential secrets:\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(w, "[%d] %s:%d\n", i+1, f.FilePath, f.LineNumber)
		fmt.Fprintf(w, "    Type: %s\n", f.SecretType)
		fmt.Fprintf(w, "    Match: %s\n\n", f.Value)
	}
	return nil
}
