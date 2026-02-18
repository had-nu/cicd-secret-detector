# CI/CD Secret Detector

A Go tool designed to catch hardcoded secrets in files before they reach production. It focuses on simplicity, reliability, and ease of integration into CI/CD pipelines.

## Features

- **Pattern Matching**: Detects common secrets like:
  - AWS Access Key IDs & Secret Access Keys
  - Private Keys (RSA, DSA, EC, OPENSSH)
  - Generic API Keys / Tokens (high entropy strings)
- **CI/CD Integration**: Exits with a non-zero status code (1) if secrets are found, blocking the build.
- **Efficient Scanning**: Recursive directory traversal with concurrency (via worker pool pattern).
- **Format Agnostic**: Scans any text file (YAML, JSON, Dockerfile, etc.), respecting `.git`, `node_modules`, and `vendor` ignores.

## Installation

```bash
go install github.com/hadnu/cicd-secret-detector/cmd/secret-detector@latest
```

Or build from source:

```bash
git clone https://github.com/hadnu/cicd-secret-detector.git
cd cicd-secret-detector
go build -o secret-detector cmd/secret-detector/main.go
```

## Usage

### Basic Scan
Scan the current directory recursively:

```bash
./secret-detector
```

### Specify Directory
Scan a specific path:

```bash
./secret-detector -dir /path/to/project
```

### Output Format
Output findings in JSON format for easier parsing by other tools:

```bash
./secret-detector -dir . -format json
```

### Example Output (Text)

```
Scanning testdata/manual...
Scanned in 165.07µs. Found 1 secrets.
Found 1 potential secrets:

[1] testdata/manual/secrets.txt:1
    Type: AWS Access Key ID
    Match: aws_access_key_id = AKIAIOSFODNN7EXAMPLE
```

## Development

This project adheres to strict idiomatic Go principles:
- **Vertical Slices**: Code is organized by feature (`scanner`, `detector`, `reporter`), not layer.
- **Standard Library First**: External dependencies are avoided unless absolutely necessary.
- **Boring Code**: Clarity and simplicity are prioritized over cleverness.

### Running Tests

```bash
go test -v ./...
```

### Project Structure

```
cicd-secret-detector/
├── bin/
├── cmd/
│   └── secret-detector/
├── internal/
│   ├── detector/
│   ├── scanner/
│   ├── reporter/
│   └── types/
└── testdata/              # Test fixtures
```
