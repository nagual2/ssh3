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

// F-15: at the cap the map used to be fail-closed — a brand-new legitimate ID
// was dropped for as long as junk IDs held all 256 slots. The oldest dangling
// queue is now evicted instead, so a fresh ID is always accepted while the
// bound (and its memory) stays.
func TestDanglingQueueEvictsOldestAtCap(t *testing.T) {
	m := newChannelsManager()
	for i := 0; i < maxDanglingDatagramQueues; i++ {
		m.addDanglingDatagramsQueue(util.ChannelID(i), []byte{byte(i)})
	}
	m.addDanglingDatagramsQueue(util.ChannelID(maxDanglingDatagramQueues), []byte("newest"))
	if len(m.danglingDgramQueues) != maxDanglingDatagramQueues {
		t.Fatalf("dangling queue count = %d, want the cap %d", len(m.danglingDgramQueues), maxDanglingDatagramQueues)
	}
	if _, ok := m.danglingDgramQueues[0]; ok {
		t.Error("the oldest dangling queue (ID 0) was not evicted")
	}
	queue, ok := m.danglingDgramQueues[util.ChannelID(maxDanglingDatagramQueues)]
	if !ok {
		t.Fatal("the newest ID was dropped at the cap instead of evicting the oldest entry")
	}
	if got := queue.Next(); string(got) != "newest" {
		t.Errorf("the newest queue holds %q, want %q", got, "newest")
	}
}

// a registered channel must no longer be an eviction candidate: its queue was
// handed over by addChannel, so evicting it would waste the slot on a no-op
// delete and keep junk alive
func TestDanglingEvictionSkipsRegisteredChannels(t *testing.T) {
	m := newChannelsManager()
	m.addDanglingDatagramsQueue(7, []byte("for-7"))
	ch := &channelImpl{ChannelInfo: ChannelInfo{ChannelID: 7}, datagramsQueue: util.NewDatagramsQueue(8)}
	m.addChannel(ch) // consumes the dangling queue and drops 7 from the eviction order

	for i := 0; i < maxDanglingDatagramQueues+1; i++ {
		m.addDanglingDatagramsQueue(util.ChannelID(100+i), []byte("junk"))
	}
	if len(m.danglingDgramQueues) != maxDanglingDatagramQueues {
		t.Fatalf("dangling queue count = %d, want the cap", len(m.danglingDgramQueues))
	}
	if _, ok := m.danglingDgramQueues[100]; ok {
		t.Error("the oldest junk queue (ID 100) survived an eviction round")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := ch.ReceiveDatagram(ctx); err != nil || string(got) != "for-7" {
		t.Errorf("the registered channel lost its queued datagram: got %q, %v", got, err)
	}
}
