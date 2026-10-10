package ssh3

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/util"
)

// nopWriteCloser satisfies the send side of a channel without a QUIC stream;
// it counts closes so tests can assert teardown happened exactly once.
type nopWriteCloser struct {
	closes atomic.Int32
}

func (w *nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (w *nopWriteCloser) Close() error                { w.closes.Add(1); return nil }

// P4-01: a datagram naming a channel that is never registered used to pin a
// dangling queue — and its buffered datagrams — for the conversation's whole
// lifetime, with no cap: an authenticated peer could grow the map at will by
// cycling channel IDs. The number of dangling queues must be bounded.
func TestDanglingDatagramQueuesBounded(t *testing.T) {
	m := newChannelsManager()
	for i := 0; i < maxDanglingDatagramQueues+16; i++ {
		m.addDanglingDatagramsQueue(util.ChannelID(i), []byte{byte(i)})
	}
	if len(m.danglingDgramQueues) != maxDanglingDatagramQueues {
		t.Errorf("dangling queue count = %d, want the cap %d (unbounded growth)", len(m.danglingDgramQueues), maxDanglingDatagramQueues)
	}
}

// the cap must not break the legitimate race: a datagram that arrived before
// its channel registered is still delivered once the channel shows up
func TestDanglingQueueDeliveredOnChannelRegistration(t *testing.T) {
	m := newChannelsManager()
	m.addDanglingDatagramsQueue(7, []byte("early"))
	ch := &channelImpl{ChannelInfo: ChannelInfo{ChannelID: 7}, datagramsQueue: util.NewDatagramsQueue(8)}
	m.addChannel(ch)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := ch.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("the datagram buffered before registration was lost: %s", err)
	}
	if string(got) != "early" {
		t.Errorf("got %q, want %q", got, "early")
	}
}

// P4-02: the close listener was wired at construction but never invoked, so
// every channel — including one the budget refused right after AcceptChannel
// registered it — stayed in the manager for the conversation's lifetime.
// Closing the channel must prune it.
func TestCloseRemovesChannelFromManager(t *testing.T) {
	m := newChannelsManager()
	send := &nopWriteCloser{}
	ch := &channelImpl{ChannelInfo: ChannelInfo{ChannelID: 43}, send: send, channelCloseListener: m}
	m.addChannel(ch)
	ch.Close()
	if _, ok := m.getChannel(43); ok {
		t.Error("the closed channel is still registered in the manager (leak)")
	}
	ch.Close() // a second close must not panic or re-register
	if _, ok := m.getChannel(43); ok {
		t.Error("the channel came back after a repeated close")
	}
	if closes := send.closes.Load(); closes != 2 {
		t.Errorf("send side closed %d times, want 2", closes)
	}
}

// a channel built without a listener must close safely
func TestCloseWithoutListener(t *testing.T) {
	ch := &channelImpl{ChannelInfo: ChannelInfo{ChannelID: 44}, send: &nopWriteCloser{}}
	ch.Close()
}
