# Vexil

A Go tool designed to catch hardcoded secrets in files before they reach production. It focuses on simplicity, reliability, and ease of integration into CI/CD pipelines.

## Features

- **Pattern Matching**: Detects common secrets like:
  - AWS Access Key IDs & Secret Access Keys
  - Private Keys (RSA, DSA, EC, OPENSSH)
  - Generic API Keys & Tokens
- **Entropy Filtering**: Reduces false positives by measuring the Shannon entropy of matched values. Broad patterns (e.g. `api_key`, `token`) only flag values that score above 3.5 bits/char* — the threshold that separates human-readable placeholders from cryptographically generated secrets.
- **Confidence Scoring**: Exposes the mathematical subset of the entropy match (Low, Medium, High, Critical) allowing downstream tools (like Wardex) to ingest non-binary risk metrics.
- **CI/CD Integration**: Exits with a non-zero status code (`1`) if secrets are found, blocking the build.
- **Efficient Scanning**: Recursive directory traversal with concurrency (via worker pool pattern).
- **Format Agnostic**: Scans any text file (YAML, JSON, Dockerfile, etc.), respecting `.git`, `node_modules`, and `vendor` ignores.

## How False Positive Reduction Works

Broad regex patterns inevitably match non-secret strings like:

```yaml
token: test-token-local-dev
api_key: your_api_key_here_1234
```

**Shannon entropy** (`H = -Σ p·log₂p`) measures how random a string is in bits per character. Real secrets produced by cryptographic functions (UUIDs, base64-encoded keys) score **above 3.5 bits/char**. Human-readable strings score below 3.0.

| Value | Entropy | Flagged? |
|---|---|---|
| `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | 0.0 bits | ✗ No |
| `changemechangemechangemech` | ~2.8 bits | ✗ No |
| `abcdefghabcdefghabcdefghab` (8-symbol cycle) | 3.0 bits | ✗ No |
| `x7Kp2mQnR9vLwZ4sXqY8nP3r` | ~4.5 bits | ✓ Yes |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | ~4.1 bits | ✓ Yes |

> **Note:** Sequential alphabet (`abcdefghijklmnopqrstuvwxyz`) has ~4.8 bits of entropy (29 unique chars) and *is* correctly flagged. Low entropy requires **few unique symbols repeated often**, not just human-predictable ordering.

Patterns that are specific enough by regex alone (AWS Access Key ID prefix `AKIA...`, PEM headers) skip the entropy check entirely.

## Installation

```bash
go install github.com/had-nu/vexil/cmd/vexil@latest
```

Or build from source:

```bash
git clone https://github.com/had-nu/vexil.git
cd vexil
go build -o vexil cmd/vexil/main.go
```

### Docker (recommended if Go is not installed)

```bash
# Build the image
docker compose build

# Run a scan
docker compose run vexil

# Scan with JSON output
docker compose run vexil -dir /src -format json
```

## Usage

```bash
# Scan current directory
./vexil

# Scan a specific path
./vexil -dir /path/to/project

# JSON output (for downstream tooling)
./vexil -dir . -format json
```

### Example Output (Text)

```
Scanning testdata/manual...
Scanned in 165.07µs. Found 1 secrets.
Found 1 potential secrets:

[1] testdata/manual/secrets.txt:1
    Type: AWS Access Key ID
    Confidence: Critical (Entropy: 0.00)
    Match: aws_access_key_id = AKIAIOSFODNN7EXAMPLE
```

## Running Tests

```bash
go test -v ./...
```

The test suite covers:

- **True positives** — real secrets that must be detected
- **Redaction** — raw secret values must never appear in output
- **False positives** — low-entropy placeholder values that must not be flagged
- **Entropy boundary** — values just below and above the 3.5 threshold
- **Confidence Scoring** — validates boundaries for internal downstream tools
- **`shannonEntropy` unit tests** — deterministic checks with known reference values

## Project Structure

```
vexil/
├── bin/
├── cmd/
│   └── vexil/              # Entry point
├── internal/
│   ├── detector/           # Pattern matching + entropy filtering + score
│   ├── scanner/            # File traversal + worker pool
│   ├── reporter/           # Output formatting (text, JSON)
│   └── types/              # Shared types (Finding)
└── testdata/               # Test fixtures
```
