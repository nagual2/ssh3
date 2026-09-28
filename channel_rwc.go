// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh3

import (
	"io"

	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// ChannelReadWriteCloser adapts an ssh3 Channel to io.ReadWriteCloser so
// stream-oriented protocols (e.g. an SFTP subsystem) can run over it. Reads
// yield only the payloads of data messages: the adapter must be the sole
// consumer of the channel's receive side, since it pulls raw messages.
type ChannelReadWriteCloser struct {
	channel Channel
	pending []byte
}

func NewChannelReadWriteCloser(channel Channel) *ChannelReadWriteCloser {
	return &ChannelReadWriteCloser{channel: channel}
}

func (c *ChannelReadWriteCloser) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		message, err := c.channel.NextMessage()
		if err != nil {
			// io.EOF propagates so protocol stacks treat it as a clean end
			return 0, err
		}
		if data, ok := message.(*ssh3Messages.DataOrExtendedDataMessage); ok {
			c.pending = []byte(data.Data)
		}
		// other message kinds (e.g. channel requests) carry no byte stream
		// payload for a data channel and are skipped
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ChannelReadWriteCloser) Write(p []byte) (int, error) {
	return c.channel.WriteData(p, ssh3Messages.SSH_EXTENDED_DATA_NONE)
}

func (c *ChannelReadWriteCloser) Close() error {
	c.channel.Close()
	return nil
}

// Compile-time interface checks.
var (
	_ io.ReadWriteCloser = (*ChannelReadWriteCloser)(nil)
)
