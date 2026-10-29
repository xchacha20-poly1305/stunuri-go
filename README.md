# stunuri

[![Go Reference](https://pkg.go.dev/badge/github.com/xchacha20-poly1305/stunuri-go.svg)](https://pkg.go.dev/github.com/xchacha20-poly1305/stunuri-go)

A Go parser for STUN and TURN URIs defined by [RFC 7064](https://www.rfc-editor.org/rfc/rfc7064)
and [RFC 7065](https://www.rfc-editor.org/rfc/rfc7065).

Requires Go 1.22 or later. No external dependencies.

## Install

```sh
go get github.com/xchacha20-poly1305/stunuri-go@latest
```

## Usage

```go
uri, err := stunuri.Parse("turns:example.org:5349?transport=tcp")
if err != nil {
    // Handle the invalid URI.
    return err
}
// uri.Scheme    == "turns"
// uri.Host      == "example.org"
// uri.Port      == "5349"
// uri.Transport == "tcp"
// uri.Secure()  == true
// uri.String()  == "turns:example.org:5349?transport=tcp"
```

Import `github.com/xchacha20-poly1305/stunuri-go`.

`Parse` accepts the opaque schemes `stun:`, `stuns:`, `turn:`, and `turns:`.
It rejects hierarchical URLs such as `stun://example.org`, user information,
paths, fragments, and queries other than TURN's single `transport` parameter.
STUN URIs do not allow a query.

The scheme is normalized to lowercase. Host, port, and transport retain their
original spelling, including host percent-encoding and brackets around IP
literals. An omitted or empty port and an omitted transport remain empty.

`URI.String()` builds a URI from its stored components without validation or
escaping. Empty port and transport fields are omitted, so parsing and rebuilding
`stun:example.org:` produces `stun:example.org`.

Parsing validates syntax only. Callers choose defaults, resolve hosts, decode
registered names, validate numeric port ranges, and reject unsupported transport
extensions or IPvFuture literals. Secure UDP URIs are syntactically accepted;
a caller that does not implement DTLS must reject them. This package does not
implement RFC 5928 server discovery or send STUN/TURN messages.

## Tests

```sh
go test -race -cover ./...
```

Tests cover every example in Appendix A of both RFCs, plus valid and invalid
host, port, transport, and URI syntax.

## License

[MIT](LICENSE).
