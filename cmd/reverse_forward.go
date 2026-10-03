package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/francoismichel/ssh3/client"
	"github.com/francoismichel/ssh3/util"
)

// reverseForwardFlags backs the repeatable -R flag. Each value follows the
// OpenSSH local-flavor syntax extended with an explicit UDP marker:
//
//	[bind_address:]bind_port[/udp]:target_host:target_port
//
// TCP is the default; the /udp suffix after the bind port selects UDP
// forwarding. An omitted bind_address (and "localhost", "127.0.0.1", "::1")
// binds the server's loopback only; "*" (and 0.0.0.0/::) request a wildcard
// bind, which the server allows but logs a warning for. The target is
// resolved on the client, like OpenSSH does.
type reverseForwardFlags []client.ReverseForward

func (f *reverseForwardFlags) String() string {
	specs := make([]string, len(*f))
	for i, forward := range *f {
		specs[i] = forward.SpecString()
	}
	return strings.Join(specs, ",")
}

func (f *reverseForwardFlags) Set(value string) error {
	forward, err := parseReverseForwardSpec(value)
	if err != nil {
		return err
	}
	*f = append(*f, forward)
	return nil
}

// parseReverseForwardSpec parses one -R specification. See the
// reverseForwardFlags documentation for the accepted forms.
func parseReverseForwardSpec(spec string) (client.ReverseForward, error) {
	parts := splitOutsideBrackets(spec, ':')
	if len(parts) != 3 && len(parts) != 4 {
		return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: expected [bind_address:]bind_port[/udp]:target_host:target_port", spec)
	}
	bindHost := ""
	bindPortPart := parts[0]
	if len(parts) == 4 {
		bindHost = unbracket(parts[0])
		bindPortPart = parts[1]
	}
	targetHost := unbracket(parts[len(parts)-2])
	targetPortPart := parts[len(parts)-1]

	if bindHost == "*" {
		// OpenSSH wildcard marker: bind every interface (dual-stack)
		bindHost = "::"
	}

	protocol := util.SSHForwardingProtocolTCP
	if bindPort, suffix, found := strings.Cut(bindPortPart, "/"); found {
		switch suffix {
		case "tcp":
		case "udp":
			protocol = util.SSHProtocolUDP
		default:
			return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: unknown protocol suffix %q (expected /tcp or /udp)", spec, suffix)
		}
		bindPortPart = bindPort
	}

	bindPort, err := parsePort(bindPortPart)
	if err != nil {
		return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: %s", spec, err)
	}
	targetPort, err := parsePort(targetPortPart)
	if err != nil {
		return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: %s", spec, err)
	}
	if targetPort == 0 {
		return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: the target port cannot be 0", spec)
	}
	if targetHost == "" {
		return client.ReverseForward{}, fmt.Errorf("invalid -R specification %q: the target host cannot be empty", spec)
	}
	return client.ReverseForward{
		BindHost:   bindHost,
		BindPort:   bindPort,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   protocol,
	}, nil
}

// parsePort parses a TCP/UDP port number; 0 is allowed on bind ports
// (ephemeral bind) and rejected for target ports by the caller.
func parsePort(port string) (uint16, error) {
	parsed, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("could not convert port %q to int", port)
	}
	if parsed < 0 || parsed > 0xFFFF {
		return 0, fmt.Errorf("port %d out of range", parsed)
	}
	return uint16(parsed), nil
}

// splitOutsideBrackets splits on separator, ignoring separators inside
// [brackets] so that IPv6 literals like [::1]:8080 stay in one part.
func splitOutsideBrackets(s string, separator byte) []string {
	var parts []string
	inBrackets := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			inBrackets = true
		case ']':
			inBrackets = false
		case separator:
			if !inBrackets {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// unbracket strips the [] around an IPv6 literal.
func unbracket(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}
