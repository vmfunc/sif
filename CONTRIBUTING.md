# Contributing

Thank you for taking the time to contribute to sif! All contributions are valued, and no contribution is too small or insignificant.
If you want to contribute but don't know where to start, worry not; there is no shortage of things to do.  
Even if you don't know any Go, don't let that stop you from trying to contribute! We're here to help.

*By contributing to this repository, you agree to adhere to the sif [Code of Conduct](https://github.com/dropalldatabases/sif/blob/main/CODE_OF_CONDUCT.md). Not doing so may result in a ban.*

## How can I help?

Here are some ways to get started:
- Have a look at our [issue tracker](https://github.com/dropalldatabases/sif/issues).
- If you've encountered a bug, discuss it with us, [report it](#reporting-issues).
- Once you've found a bug you believe you can fix, open a [pull request](#contributing-code) for it.
- Alternatively, consider [packaging sif for your distribution](#packaging).

If you like the project, but don't have time to contribute, that's okay too! Here are other ways to show your appreciation for the project:
- Use sif (seriously, that's enough)
- Star the repository
- Share sif with your friends
- Support us on Liberapay (thank you!)

## Reporting issues

If you believe you've found a bug, or you have a new feature to request, please hop on the [Discord server](https://discord.gg/dropalldatabases) first to discuss it.  
This way, if it's an easy fix, we could help you solve it more quickly, and if it's a feature request we could workshop it together into something more mature.

When opening an issue, please use the search tool and make sure that the issue has not been discussed before. In the case of a bug report, run sif with the `-d/-debug` flag for full debug logs.

## Contributing code

### Development

To develop sif, you'll need version 1.23 or later of the Go toolchain. After making your changes, run the program using `go run ./cmd/sif` to make sure it compiles and runs properly.

*Nix users:* the repository provides a flake that can be used to develop and run sif. Use `nix run`, `nix develop`, `nix build`, etc. Make sure to run `gomod2nix` if `go.mod` is changed.

### Submitting a pull request

When making a pull request, please adhere to the following conventions:

- sif adheres to the Go style guidelines. Always format your gode with `gofmt`.
- When adding/removing imports, make sure to use `go mod tidy`, and then run `gomod2nix` to generate the Nix-readable module list.
- Set `git config pull.rebase true` to rebase commits on pull instead of creating ugly merge commits.
- Title your commits in present tense, in the imperative style.
  - You may use prefixes like `feat`, `fix`, `chore`, `deps`, etc.  
    **Example:** `deps: update gopkg.in/yaml.v3 to v3.0.1`
  - You may use prefixes to denote the part of the code changed in the commit.  
    **Example:** `pkg/scan: ignore 3xx redirects`
  - If not using a prefix, make sure to use sentence case.  
    **Example:** `Add nuclei template parsing support`
  - If applicable, provide a helpful commit description, listing usage notes, implementation details, and tasks that still need to be done.

If you have any questions, feel free to ask around on the IRC channel.

## Contributing Framework Detection Patterns

The framework detection module (`pkg/scan/frameworks/detect.go`) identifies web frameworks by analyzing HTTP headers and response bodies. To add support for a new framework:

### Adding a New Framework Signature

1. Add your framework to the `frameworkSignatures` map:

```go
"MyFramework": {
    {Pattern: `unique-identifier`, Weight: 0.5},
    {Pattern: `header-signature`, Weight: 0.4, HeaderOnly: true},
    {Pattern: `body-signature`, Weight: 0.3},
},
```

**Pattern Guidelines:**
- `Weight`: How much this signature contributes to detection (0.0-1.0)
- `HeaderOnly`: Set to `true` for HTTP header patterns
- Use unique identifiers that won't false-positive on other frameworks
- Include multiple patterns for higher confidence

### Adding Version Detection

Add version patterns to `extractVersionWithConfidence()`:

```go
"MyFramework": {
    {`MyFramework[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
    {`"myframework":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
},
```

### Adding CVE Data

Add known vulnerabilities to the `knownCVEs` map:

```go
"MyFramework": {
    {
        CVE:              "CVE-YYYY-XXXXX",
        AffectedVersions: []string{"1.0.0", "1.0.1", "1.1.0"},
        FixedVersion:     "1.2.0",
        Severity:         "high",  // critical, high, medium, low
        Description:      "Brief description of the vulnerability",
        Recommendations:  []string{"Update to 1.2.0 or later"},
    },
},
```

### Testing Your Changes

Always add tests for new frameworks in `detect_test.go`:

```go
func TestDetectFramework_MyFramework(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`<html><body>unique-identifier</body></html>`))
    }))
    defer server.Close()

    result, err := DetectFramework(server.URL, 5*time.Second, "")
    // assertions...
}
```

### Future Enhancements (Help Wanted)

- **Custom Signature Support**: Allow users to define signatures via config file
- **CVE API Integration**: Real-time CVE data from NVD or other sources
- **Automated Signature Updates**: Fetch new signatures from a central repository
- **Framework Fingerprint Database**: Community-maintained signature database

## Configuration

### Framework Detection Flags

| Flag | Description |
|------|-------------|
| `-framework` | Enable framework detection |
| `-timeout` | HTTP request timeout (affects all modules) |
| `-threads` | Number of concurrent workers |
| `-log` | Directory to save scan results |
| `-debug` | Enable debug logging for verbose output |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHODAN_API_KEY` | API key for Shodan host intelligence |

## Packaging

We'd love it if you helped us bring sif to your distribution.
The repository provides a Makefile for building and packaging sif for any distro; consult your distribution's documentation for details.
