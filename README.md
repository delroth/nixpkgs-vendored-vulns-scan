# nixpkgs vendored vulnerabilities scanner

Infrastructure to scan for vulnerabilities in nixpkgs packages that vendor
their dependencies, e.g. Rust / NPM / Go / Java / .NET.

## Status

Very WIP. Currently working:

- Scanning
  - Ecosystems
    - Rust
    - NPM

Not working:

- Scanning
  - Ecosystems
    - Go
    - Java (Maven)
    - .NET (NuGet)
  - Proper JSON output
  - Reporting to API endpoint
- API
  - Scan results submission + storage over time
- Frontend
- Plumbing
  - NixOS services

## How to use

```
$ nix develop
$ cd vendoredvulns/scanner
$ poetry install
$ poetry run vendored-vulns-scanner -i /path/to/nixpkgs
```
