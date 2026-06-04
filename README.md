# CertCheck
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)
![License](https://img.shields.io/github/license/r0thko/certcheck)
![Last Commit](https://img.shields.io/github/last-commit/r0thko/certcheck)

A simple TLS certificate expiration checker written in Go.

CertCheck reads a list of endpoints, retrieves their TLS certificates, and displays certificate details together with expiration status.

## Features

- Check TLS certificates for multiple endpoints
- Supports both implicit and explicit ports
- Defaults to port `443` when no port is specified
- Ignores blank lines and comments (`#`)
- Displays:
  - Endpoint
  - Certificate Common Name (CN)
  - Expiration date
  - Days remaining
  - Expiration severity
- Highlights certificates approaching expiration
- Reports failed checks in a dedicated table
- Classifies common connection errors
- Dynamic table formatting based on content width
- Command-line argument support for endpoint files

## Installation

Clone the repository:

```bash
git clone https://github.com/r0thko/certcheck.git
cd certcheck
```

Build:

```bash
go build -o certcheck
```

## Usage

Run CertCheck and provide an endpoints file:

```bash
./certcheck endpoints.example.list
```

You can also use your own file:

```bash
./certcheck production.list
```

## Endpoint Format

Lines beginning with `#` are treated as comments and ignored.

Endpoints may be specified with or without a port.

Example:

```text
# Standard HTTPS endpoint
stackoverflow.com

# Explicit HTTPS port
github.com:443

# Example endpoint with a custom TLS port
google.com:8443

# Example internal service running TLS on a custom port
your-internal-platform.example:6443
```

When no port is specified, CertCheck automatically uses:

```text
443
```

## Example Output

```text
ENDPOINT              | COMMON NAME       | EXPIRES    | STATUS       | REMARK
stackoverflow.com:443 | stackoverflow.com | 2026-07-18 | 43 days left |
sff.pl:443            | sff.pl            | 2026-06-25 | 20 days left | WARNING
github.com:443        | github.com        | 2026-08-02 | 59 days left |

FAILED CHECKS
-------------
ENDPOINT                            | ERROR
google.com:8443                     | connection timeout
your-internal-platform.example:6443 | host not found
```

## Warning Levels

Current thresholds:

| Severity | Days Remaining |
|----------|-----------------|
| WARNING  | Less than 30 days |
| CRITICAL | Less than 15 days |

These values can be adjusted in the source code:

```go
const (
    CriticalTime = 15
    WarningTime  = 30
)
```

## Error Handling

Endpoints that cannot be checked are reported separately under the `FAILED CHECKS` section.

Current error classifications include:

- Host not found (DNS resolution failure)
- Connection timeout

Additional classifications may be added in future releases.

## Roadmap

- [ ] Concurrent certificate checks using goroutines
- [ ] JSON output
- [ ] Configurable warning thresholds
- [ ] Better error classification
- [ ] Exit codes for monitoring integrations
- [ ] Unit tests

## License

MIT