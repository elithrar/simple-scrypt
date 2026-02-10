# AGENTS.md

Guidelines for AI agents operating in the `simple-scrypt` repository.

## Project overview

Single-package Go library wrapping `golang.org/x/crypto/scrypt` for password hashing.
Module path: `github.com/elithrar/simple-scrypt`. One external dependency (`golang.org/x/crypto`).

Two source files at the repo root:
- `scrypt.go` — library implementation (public API mirrors Go's `bcrypt` package)
- `scrypt_test.go` — tests (standard `testing` package, no third-party frameworks)

Hash format: `N$R$P$hexsalt$hexdk` (dollar-separated, hex-encoded salt and derived key).

Default branch is **`main`**.

## Build and test commands

```sh
# build
go build ./...

# run full test suite (CI uses this exact command)
go test -v -race ./...

# run a single test
go test -v -race -run TestCompareHashAndPassword ./...

# run a single sub-test (table-driven)
go test -v -race -run TestCalibrate/512 ./...

# formatting check — CI rejects any diff
gofmt -l .

# apply formatting fixes
gofmt -w .

# static analysis — CI runs this
go vet ./...
```

CI runs on push/PR to `main` across Go 1.21, 1.22, 1.23, 1.24 plus tip on Ubuntu.
All three checks must pass: `gofmt`, `go vet`, `go test -v -race ./...`.

Always run `go test -v -race ./...` before committing to catch data races and regressions.

## Code style

### Formatting

`gofmt` is the only formatter. No custom config. CI enforces zero diff — run `gofmt -w .` before committing.

### Imports

Standard library first, blank line, then external packages:

```go
import (
    "crypto/rand"
    "errors"
    "fmt"

    "golang.org/x/crypto/scrypt"
)
```

### Naming

- Exported types/functions: `PascalCase` — `Params`, `GenerateFromPassword`, `CompareHashAndPassword`
- Unexported functions/constants: `camelCase` — `decodeHash`, `maxInt`, `minDKLen`
- Sentinel errors: `Err` prefix — `ErrInvalidHash`, `ErrInvalidParams`, `ErrMismatchedHashAndPassword`
- Receiver names: short, single letter — `p` for `*Params`

### Error handling

- Sentinel errors as package-level `var` using `errors.New()`
- Functions return `error` as the last return value
- Early return on error (guard clauses) — no nested else blocks
- No error wrapping in this codebase; return sentinel errors or upstream errors directly
- `CompareHashAndPassword` returns `nil` on success (bcrypt convention)

```go
var ErrInvalidHash = errors.New("scrypt: the provided hash is not in the correct format")

func Cost(hash []byte) (Params, error) {
    params, _, _, err := decodeHash(hash)
    return params, err
}
```

### Comments

- Godoc comments on all exported types, functions, and variables
- Internal comments explain *why*, not *what* — save them for I/O, validation, and edge cases
- Don't comment single variables or trivial functions

### Testing

Standard `testing` package only. Tests are in `package scrypt` (white-box, same package).

Patterns used in this codebase:

- **Table-driven tests** with `pass bool` fields for expected outcomes:
  ```go
  var testParams = []struct {
      pass   bool
      params Params
  }{
      {true, Params{16384, 8, 1, 32, 64}},
      {false, Params{-1, 8, 1, 16, 32}},
  }
  ```
- `t.Fatal` / `t.Fatalf` for hard failures that should stop the test
- `t.Errorf` for soft failures (test continues to check remaining cases)
- `t.Logf` for informational output (e.g., timing data)
- `Example*` functions for godoc examples

Do not add third-party test frameworks or assertion libraries.
Avoid tests that merely exercise language features — focus on validation, state, and error handling.

### Types

- Do not use type casts to work around type issues; fix the underlying problem
- Zero-value structs (e.g., `Params{}`) are used as signals for default behavior (see `Calibrate`)

## Dependencies

Minimize new dependencies. The library has one external dependency by design.
Install dependencies using `go get`. Ensure `go.sum` is committed alongside `go.mod` changes.

## Git and PR conventions

- Short, imperative commit messages: `add calibration benchmarks` not `feat(scrypt): added calibration benchmarks`
- Do not commit, push, or create PRs without explicit instruction
- Use `gh` CLI for creating PRs and issues
- Branch off `main` for new work; never commit directly to `main`
- PRs: short opening sentence with the "why", bullet points for major changes, mention related docs/tests
- Do not list changed files in PR descriptions — the diff shows that
