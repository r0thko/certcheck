# CertCheck

A simple TLS certificate expiration checker written in Go.

CertCheck reads a list of endpoints, retrieves their TLS certificates, and displays certificate details together with expiration status.

## Features

- Check TLS certificates for multiple endpoints
- Supports both implicit and explicit ports
- Defaults to port `443` when no port is specified
- Displays:
    - Endpoint
    - Certificate Common Name (CN)
    - Expiration date
    - Days remaining
    - Warning status
- Highlights certificates approaching expiration
- Dynamic table formatting based on content width
- Command-line argument support for endpoint files

## Installation

Clone the repository:

```bash
git clone git@github.com:r0thko/certcheck.git
cd certcheck
```

Build:

```bash
go build -o certcheck
```

## Usage

Create an endpoints file:

```text
google.com
sff.pl
gobyexample.com
internal-api.company.com:8443
```

Run:

```bash
./certcheck endpoints.list
```

Example output:

```text
ENDPOINT            | COMMON NAME     | EXPIRES    | STATUS        | REMARK
sowinski.st:443     | sowinski.st     | 2026-07-28 | 53 days left  |
google.com:443      | *.google.com    | 2026-08-10 | 67 days left  |
sff.pl:443          | sff.pl          | 2026-06-25 | 20 days left  | WARNING
gobyexample.com:443 | gobyexample.com | 2027-01-17 | 227 days left |
```

## Endpoint Format

Endpoints may be specified with or without a port.

Examples:

```text
google.com
sff.pl
example.com:8443
```

When no port is specified, CertCheck automatically uses:

```text
443
```

## Warning Levels

Current thresholds:

| Severity | Days Remaining |
|-----------|----------------|
| WARNING | Less than 30 days |
| CRITICAL | Less than 15 days |

These values can be adjusted in the source code:

```go
const (
    CriticalTime = 15
    WarningTime  = 30
)
```

## Project Goals

This project was created as a practical Go learning project while exploring:

- File I/O
- Structs and custom types
- Error handling
- TLS certificate inspection
- Terminal output formatting
- Command-line applications
- Git and GitHub workflows

## Roadmap

- [ ] Concurrent certificate checks using goroutines
- [ ] JSON output
- [ ] Configurable warning thresholds
- [ ] Exit codes for monitoring integrations
- [ ] Export results to files
- [ ] Unit tests

## License

MIT