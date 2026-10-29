package stunuri

import "testing"

func TestRFC7064Examples(t *testing.T) {
	// All examples from https://www.rfc-editor.org/rfc/rfc7064#appendix-A.
	for _, test := range []struct {
		input  string
		scheme string
		port   string
		secure bool
	}{
		{"stun:example.org", "stun", "", false},
		{"stuns:example.org", "stuns", "", true},
		{"stun:example.org:8000", "stun", "8000", false},
	} {
		t.Run(test.input, func(t *testing.T) {
			uri, err := Parse(test.input)
			if err != nil {
				t.Fatal(err)
			}
			want := URI{Scheme: test.scheme, Host: "example.org", Port: test.port}
			if *uri != want {
				t.Fatalf("Parse() = %+v, want %+v", *uri, want)
			}
			if uri.Secure() != test.secure {
				t.Fatalf("Secure() = %v, want %v", uri.Secure(), test.secure)
			}
		})
	}
}

func TestRFC7065Examples(t *testing.T) {
	// All examples from https://www.rfc-editor.org/rfc/rfc7065#appendix-A.
	// The last row's TLS is represented by Secure() and the TCP transport.
	for _, test := range []struct {
		input     string
		scheme    string
		port      string
		transport string
		secure    bool
	}{
		{"turn:example.org", "turn", "", "", false},
		{"turns:example.org", "turns", "", "", true},
		{"turn:example.org:8000", "turn", "8000", "", false},
		{"turn:example.org?transport=udp", "turn", "", "udp", false},
		{"turn:example.org?transport=tcp", "turn", "", "tcp", false},
		{"turns:example.org?transport=tcp", "turns", "", "tcp", true},
	} {
		t.Run(test.input, func(t *testing.T) {
			uri, err := Parse(test.input)
			if err != nil {
				t.Fatal(err)
			}
			want := URI{Scheme: test.scheme, Host: "example.org", Port: test.port, Transport: test.transport}
			if *uri != want {
				t.Fatalf("Parse() = %+v, want %+v", *uri, want)
			}
			if uri.Secure() != test.secure {
				t.Fatalf("Secure() = %v, want %v", uri.Secure(), test.secure)
			}
		})
	}
}

func TestParseSyntax(t *testing.T) {
	for _, test := range []struct {
		input string
		want  URI
	}{
		{"STUN:Example.ORG", URI{Scheme: "stun", Host: "Example.ORG"}},
		{"turns:Example.ORG:005349?TRANSPORT=TCP", URI{Scheme: "turns", Host: "Example.ORG", Port: "005349", Transport: "TCP"}},
		{"stun:192.0.2.1:3478", URI{Scheme: "stun", Host: "192.0.2.1", Port: "3478"}},
		{"stun:[2001:db8::1]", URI{Scheme: "stun", Host: "[2001:db8::1]"}},
		{"stuns:[::ffff:192.0.2.1]:5349", URI{Scheme: "stuns", Host: "[::ffff:192.0.2.1]", Port: "5349"}},
		{"turn:[::]:8000?transport=tcp", URI{Scheme: "turn", Host: "[::]", Port: "8000", Transport: "tcp"}},
		{"turn:[v1.future:address]:8000", URI{Scheme: "turn", Host: "[v1.future:address]", Port: "8000"}},
		{"turn:[VF.a!$&'()*+,;=:_~-]", URI{Scheme: "turn", Host: "[VF.a!$&'()*+,;=:_~-]"}},
		{"stun:ex%61mple.org", URI{Scheme: "stun", Host: "ex%61mple.org"}},
		{"stun:a!$&'()*+,;=._~-", URI{Scheme: "stun", Host: "a!$&'()*+,;=._~-"}},
		{"stun:example.org:", URI{Scheme: "stun", Host: "example.org"}},
		{"stun:example.org:0", URI{Scheme: "stun", Host: "example.org", Port: "0"}},
		{"stun:example.org:999999999999999999999", URI{Scheme: "stun", Host: "example.org", Port: "999999999999999999999"}},
		{"turn:example.org?transport=extension-._~123", URI{Scheme: "turn", Host: "example.org", Transport: "extension-._~123"}},
		{"turns:example.org?transport=udp", URI{Scheme: "turns", Host: "example.org", Transport: "udp"}},
	} {
		t.Run(test.input, func(t *testing.T) {
			uri, err := Parse(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if *uri != test.want {
				t.Fatalf("Parse() = %+v, want %+v", *uri, test.want)
			}
		})
	}
}

func TestParseRejectsInvalidSyntax(t *testing.T) {
	for _, input := range []string{
		"", "example.org", "example.org:3478", "https:example.org", "stun", ":example.org",
		"stun:", "stuns:", "turn:", "turns:", "stun::3478", "turn:?transport=udp",
		"stun://example.org", "turn://example.org", "turns://example.org",
		"stun:example.org/path", "stun:example.org/", "turn:example.org#fragment",
		"stun:user@example.org", "turn:user:password@example.org",
		" stun:example.org", "stun:example.org ", "stun:ex ample.org", "stun:example.org\n", "stun:例子.org",
		"stun:ex%ample.org", "stun:example.org%", "stun:example.org%0", "stun:example.org%gg",
		"stun:example.org:-1", "stun:example.org:+1", "stun:example.org:abc", "stun:example.org:1:2",
		"stun:2001:db8::1", "stun:[2001:db8::1", "stun:2001:db8::1]",
		"stun:[]", "stun:[example.org]", "stun:[192.0.2.1]", "stun:[2001:db8::gg]",
		"stun:[fe80::1%eth0]", "stun:[fe80::1%25eth0]", "stun:[::1]suffix", "stun:[::1]:80/path",
		"stun:[v.future]", "stun:[v1.]", "stun:[vg.future]", "stun:[v1.a%20]",
		"stun:example.org?transport=udp", "stuns:example.org?transport=tcp", "stun:example.org?",
		"turn:example.org?", "turn:example.org?transport", "turn:example.org?transport=",
		"turn:example.org?other=udp", "turn:example.org?transport=udp&transport=tcp",
		"turn:example.org?tranſport=tcp",
		"turn:example.org?transport=tcp&other=value", "turn:example.org?transport=tcp?transport=udp",
		"turn:example.org?transport=%75dp", "turn:example.org?transport=tcp#fragment",
		"turn:example.org?transport=tcp/", "turn:example.org?transport=tcp+tls",
	} {
		t.Run(input, func(t *testing.T) {
			uri, err := Parse(input)
			if err == nil || uri != nil {
				t.Fatalf("Parse() = %+v, %v; want nil and an error", uri, err)
			}
		})
	}
}
