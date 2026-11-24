# billing-svc notes

- Build: `go build ./...`
- Run tests with the race detector: `go test -race ./...`
- Errors are wrapped with fmt.Errorf("...: %w", err).
- Do not add new global variables; pass dependencies explicitly.
