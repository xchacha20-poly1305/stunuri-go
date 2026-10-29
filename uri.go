// Package stunuri parses the STUN and TURN URI schemes defined by RFC 7064
// and RFC 7065. It validates URI syntax without choosing a transport or
// resolving a server through RFC 5928.
package stunuri

import (
	"fmt"
	"net/netip"
	"strings"
)

// URI contains the components of a STUN or TURN URI. Scheme is lowercase;
// Host, Port, and Transport retain their original spelling. Host includes
// brackets for IP literals and retains percent-encoding for registered names.
// An omitted or empty port and an omitted transport remain empty.
type URI struct {
	Scheme    string
	Host      string
	Port      string
	Transport string
}

// Secure reports whether the scheme requires a secure transport.
func (u URI) Secure() bool {
	return u.Scheme == "stuns" || u.Scheme == "turns"
}

// Parse parses an opaque stun, stuns, turn, or turns URI. TURN transport
// extensions and IPvFuture literals are accepted as specified by the RFCs;
// callers must reject mechanisms they do not implement. Ports follow RFC 3986's
// *DIGIT syntax; callers must check their numeric range before connecting.
func Parse(rawURI string) (*URI, error) {
	scheme, authority, found := strings.Cut(rawURI, ":")
	if !found {
		return nil, fmt.Errorf("missing STUN/TURN URI scheme")
	}
	uri := &URI{Scheme: strings.ToLower(scheme)}
	switch uri.Scheme {
	case "stun", "stuns", "turn", "turns":
	default:
		return nil, fmt.Errorf("unsupported STUN/TURN URI scheme: %q", scheme)
	}
	if hostPort, query, hasQuery := strings.Cut(authority, "?"); hasQuery {
		if uri.Scheme == "stun" || uri.Scheme == "stuns" {
			return nil, fmt.Errorf("STUN URIs do not allow a query")
		}
		key, transport, hasValue := strings.Cut(query, "=")
		if !hasValue || strings.ToLower(key) != "transport" || transport == "" {
			return nil, fmt.Errorf("expected a single transport parameter")
		}
		for i := range len(transport) {
			if !isUnreserved(transport[i]) {
				return nil, fmt.Errorf("invalid TURN transport: %q", transport)
			}
		}
		uri.Transport = transport
		authority = hostPort
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end == -1 || !validIPLiteral(authority[1:end]) {
			return nil, fmt.Errorf("invalid IP literal")
		}
		uri.Host = authority[:end+1]
		remainder := authority[end+1:]
		if remainder != "" {
			if remainder[0] != ':' {
				return nil, fmt.Errorf("unexpected content after IP literal")
			}
			uri.Port = remainder[1:]
		}
	} else {
		uri.Host, uri.Port, _ = strings.Cut(authority, ":")
		if !validRegisteredName(uri.Host) {
			return nil, fmt.Errorf("invalid STUN/TURN host")
		}
	}
	for i := range len(uri.Port) {
		if uri.Port[i] < '0' || uri.Port[i] > '9' {
			return nil, fmt.Errorf("invalid STUN/TURN port: %q", uri.Port)
		}
	}
	return uri, nil
}

func validRegisteredName(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		character := host[i]
		if isUnreserved(character) || isSubDelimiter(character) {
			continue
		}
		if character != '%' || i+2 >= len(host) || !isHex(host[i+1]) || !isHex(host[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func validIPLiteral(host string) bool {
	if len(host) > 0 && (host[0] == 'v' || host[0] == 'V') {
		version, address, found := strings.Cut(host[1:], ".")
		if !found || version == "" || address == "" {
			return false
		}
		for i := range len(version) {
			if !isHex(version[i]) {
				return false
			}
		}
		for i := range len(address) {
			if !isUnreserved(address[i]) && !isSubDelimiter(address[i]) && address[i] != ':' {
				return false
			}
		}
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Is6() && address.Zone() == ""
}

func isUnreserved(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("-._~", rune(character))
}

func isSubDelimiter(character byte) bool {
	return strings.ContainsRune("!$&'()*+,;=", rune(character))
}

func isHex(character byte) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}
