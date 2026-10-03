package cmd

import (
	"testing"

	"github.com/francoismichel/ssh3/client"
	"github.com/francoismichel/ssh3/util"
)

func TestParseReverseForwardSpec(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want client.ReverseForward
	}{
		{
			name: "minimal tcp",
			spec: "8080:127.0.0.1:80",
			want: client.ReverseForward{BindHost: "", BindPort: 8080, TargetHost: "127.0.0.1", TargetPort: 80, Protocol: util.SSHForwardingProtocolTCP},
		},
		{
			name: "explicit loopback bind",
			spec: "127.0.0.1:8080:10.0.0.5:80",
			want: client.ReverseForward{BindHost: "127.0.0.1", BindPort: 8080, TargetHost: "10.0.0.5", TargetPort: 80, Protocol: util.SSHForwardingProtocolTCP},
		},
		{
			name: "explicit tcp suffix",
			spec: "8080/tcp:localhost:80",
			want: client.ReverseForward{BindHost: "", BindPort: 8080, TargetHost: "localhost", TargetPort: 80, Protocol: util.SSHForwardingProtocolTCP},
		},
		{
			name: "udp suffix",
			spec: "5353/udp:127.0.0.1:53",
			want: client.ReverseForward{BindHost: "", BindPort: 5353, TargetHost: "127.0.0.1", TargetPort: 53, Protocol: util.SSHProtocolUDP},
		},
		{
			name: "wildcard bind",
			spec: "*:8080:192.0.2.1:8080",
			want: client.ReverseForward{BindHost: "::", BindPort: 8080, TargetHost: "192.0.2.1", TargetPort: 8080, Protocol: util.SSHForwardingProtocolTCP},
		},
		{
			name: "ipv6 bind and target",
			spec: "[::1]:8080:[2001:db8::1]:443",
			want: client.ReverseForward{BindHost: "::1", BindPort: 8080, TargetHost: "2001:db8::1", TargetPort: 443, Protocol: util.SSHForwardingProtocolTCP},
		},
		{
			name: "zero bind port is ephemeral",
			spec: "0:127.0.0.1:80",
			want: client.ReverseForward{BindHost: "", BindPort: 0, TargetHost: "127.0.0.1", TargetPort: 80, Protocol: util.SSHForwardingProtocolTCP},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseReverseForwardSpec(test.spec)
			if err != nil {
				t.Fatalf("parseReverseForwardSpec(%q) returned error: %s", test.spec, err)
			}
			if got != test.want {
				t.Errorf("parseReverseForwardSpec(%q) = %+v, want %+v", test.spec, got, test.want)
			}
		})
	}
}

func TestParseReverseForwardSpecErrors(t *testing.T) {
	specs := []string{
		"",                        // empty
		"8080",                    // missing target
		"8080:127.0.0.1",          // missing target port
		"8080:127.0.0.1:80:extra", // too many parts
		"port:127.0.0.1:80",       // non-numeric bind port
		"8080:127.0.0.1:port",     // non-numeric target port
		"70000:127.0.0.1:80",      // bind port out of range
		"-1:127.0.0.1:80",         // negative bind port
		"8080:127.0.0.1:0",        // target port cannot be 0
		"8080/sctp:127.0.0.1:80",  // unknown protocol suffix
		"8080/udp::80",            // empty target host
	}
	for _, spec := range specs {
		if _, err := parseReverseForwardSpec(spec); err == nil {
			t.Errorf("parseReverseForwardSpec(%q) = nil error, want an error", spec)
		}
	}
}

func TestReverseForwardFlagsString(t *testing.T) {
	var flags reverseForwardFlags
	if flags.String() != "" {
		t.Errorf("empty reverseForwardFlags String() = %q, want empty", flags.String())
	}
	for _, spec := range []string{"8080:127.0.0.1:80", "5353/udp:127.0.0.1:53"} {
		if err := flags.Set(spec); err != nil {
			t.Errorf("Set(%q) returned error: %s", spec, err)
		}
	}
	if len(flags) != 2 {
		t.Fatalf("len(flags) = %d, want 2", len(flags))
	}
	// String() renders the normalized forms back, including the /udp marker
	want := "8080:127.0.0.1:80,5353/udp:127.0.0.1:53"
	if flags.String() != want {
		t.Errorf("String() = %q, want %q", flags.String(), want)
	}
}
