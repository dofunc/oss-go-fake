# Contributing

## Ground rules

oss-go-fake mimics real OSS and nothing else. A change must match how Alibaba Cloud OSS behaves, with a link to the OSS documentation or SDK source that shows it. Parameters, headers or semantics that OSS does not have are not accepted, however handy: code that works against the fake would then break against OSS. Startup flags, the readiness line and bucket declarations are how the fake runs, not protocol, and are fine to extend.

## Code conventions

| Topic | Convention |
|---|---|
| Go version | `go.mod` declares the version, CI uses it through `go-version-file` |
| Formatting and checks | `gofmt`, `go vet` and golangci-lint (the version pinned in `.github/workflows/ci.yml`) must pass |
| Dependencies | Standard library for HTTP, XML and crypto. Third-party: `spf13/cobra` for the command line, `go.yaml.in/yaml/v3` for the config file. The official OSS Go SDK is a test-only dependency. Ask before adding anything else |
| Packages | Everything lives under `internal/`. The project ships a binary, not a library |
| Layers | `server` (listener, request id, access log, protocol detection) → `protocol/oss` (addressing, signatures, XML, error codes) → `service` (names, ACL, listing, copy semantics) → `storage` (persistence). A layer only calls the one below it |
| Errors | `service` returns `*service.Error` with a `Kind`. The protocol layer maps kinds to status codes and OSS error codes. Never swallow an error: return it or log it |
| Logging | `log/slog`, JSON to stderr, one access log line per request with its request id |
| Comments | English. Doc comments say what a function guarantees and its limits; inside functions, comment only what the code cannot say itself |
| Naming | Go conventions: MixedCaps, initialisms in one case (`RequestID`, `accessKeyID`), lower-case package names, snake_case file names |

## Tests

```sh
go test -race ./...
golangci-lint run ./...
```

- Standard `testing`, table-driven where it fits. No mocks: storage tests use `t.TempDir()`.
- Protocol behaviour is tested end to end with the official Go SDK (`internal/server/integration_test.go`), every case under both V1 and V4 signatures. Requests the SDK refuses to send, or tampered ones, are signed with the SDK's own `signer` package.
- Signature canonicalization is compared byte for byte with the test vectors published in the SDK's `signer_test.go`.
- `cmd/oss-go-fake` tests run the real command in a child process to check exit codes, the readiness line and graceful shutdown.

## Releases

1. Make sure CI is green on `main`.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.
3. The `release` workflow runs GoReleaser. It publishes the five binaries (`oss-go-fake-<os>-<arch>`, linux/darwin on amd64/arm64 plus windows/amd64) with `checksums.txt` to the GitHub release, and the multi-arch image `ghcr.io/dofunc/oss-go-fake:<version>` plus `latest`.

To try a release locally without publishing:

```sh
goreleaser release --snapshot --clean --skip=docker
```

The binaries land in `dist/`.
