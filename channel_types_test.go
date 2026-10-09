package ssh3

import "testing"

// The channel-type role table (S2-03/P3-03): each endpoint accepts only the
// types the peer's role may open. The allow-lists must cover exactly the
// types the dispatch layers handle — the server's accept loop in
// cmd/ssh3-server.go for the client-opened set, the client's acceptLoop in
// client/reverse_forward.go for the server-opened set.
func TestServerAcceptsChannelType(t *testing.T) {
	accepted := []string{
		"session",
		"sftp",
		"direct-tcp",
		"direct-udp",
		"reverse-forward",
		"dynamic-forward",
		"dynamic-forward-tcp",
	}
	for _, channelType := range accepted {
		if !serverAcceptsChannelType(channelType) {
			t.Errorf("serverAcceptsChannelType(%q) = false, want true (dispatched client-to-server type)", channelType)
		}
	}
	refused := []string{
		"forwarded-tcp", // server-to-client only (S2-03)
		"forwarded-udp",
		"agent-connection", // server-to-client only
		"",
		"unknown-type",
		"session ",
		"SESSION",
	}
	for _, channelType := range refused {
		if serverAcceptsChannelType(channelType) {
			t.Errorf("serverAcceptsChannelType(%q) = true, want false (not a client-to-server type)", channelType)
		}
	}
}

func TestClientAcceptsChannelType(t *testing.T) {
	accepted := []string{
		"forwarded-tcp", // the -R bridge targets
		"forwarded-udp",
		"agent-connection", // ssh-agent forwarding
	}
	for _, channelType := range accepted {
		if !clientAcceptsChannelType(channelType) {
			t.Errorf("clientAcceptsChannelType(%q) = false, want true (dispatched server-to-client type)", channelType)
		}
	}
	refused := []string{
		"session",
		"sftp",
		"direct-tcp", // client-to-server only (S2-03)
		"direct-udp",
		"reverse-forward",
		"dynamic-forward",
		"",
		"unknown-type",
	}
	for _, channelType := range refused {
		if clientAcceptsChannelType(channelType) {
			t.Errorf("clientAcceptsChannelType(%q) = true, want false (not a server-to-client type)", channelType)
		}
	}
}
