package ssh3

import (
	"sync"

	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// danglingDatagramQueueSize bounds how many datagrams are buffered per channel
// while waiting for that channel to be registered by its owner.
const danglingDatagramQueueSize = 64

// maxDanglingDatagramQueues bounds how many channels may have a dangling
// queue at the same time (P4-01): each entry is a buffered queue plus its
// datagrams, retained until a channel with that ID registers or the
// conversation dies, so an unbounded map let an authenticated peer grow it
// by cycling channel IDs. Far above any legitimate concurrent-channel count,
// whose datagrams race the registration by microseconds.
const maxDanglingDatagramQueues = 256

type ControlStreamID = uint64

type conversationsManager struct {
	connection    *quic.Conn
	conversations map[ControlStreamID]*Conversation
	lock          sync.Mutex
}

func newConversationManager(connection *quic.Conn) *conversationsManager {
	return &conversationsManager{connection: connection, conversations: make(map[ControlStreamID]*Conversation)}
}

func (m *conversationsManager) addConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.conversations[uint64(conversation.controlStream.StreamID())] = conversation
}

func (m *conversationsManager) getConversation(id ControlStreamID) (*Conversation, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	conv, ok := m.conversations[id]
	return conv, ok
}

func (m *conversationsManager) removeConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.conversations, uint64(conversation.controlStream.StreamID()))
}

type channelsManager struct {
	channels            map[util.ChannelID]Channel
	danglingDgramQueues map[util.ChannelID]*util.DatagramsQueue
	// FIFO index into danglingDgramQueues, oldest first (F-15): at the cap
	// the oldest junk queue is evicted instead of dropping a brand-new ID,
	// which left the map fail-closed for the conversation's whole lifetime.
	// Mutated only under lock, always together with the map.
	danglingOrder []util.ChannelID
	lock          sync.Mutex
}

func newChannelsManager() *channelsManager {
	return &channelsManager{channels: make(map[util.ChannelID]Channel), danglingDgramQueues: make(map[util.ChannelID]*util.DatagramsQueue)}
}

func (m *channelsManager) addChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if dgramsQueue, ok := m.danglingDgramQueues[channel.ChannelID()]; ok {
		channel.setDgramQueue(dgramsQueue)
		delete(m.danglingDgramQueues, channel.ChannelID())
		m.danglingOrder = removeChannelID(m.danglingOrder, channel.ChannelID())
	}
	m.channels[util.ChannelID(channel.ChannelID())] = channel
}

// addDanglingDatagramsQueue buffers a datagram that arrived before its channel
// was registered. Datagrams for the same channel accumulate in a single queue:
// storing a fresh queue per arrival would silently drop everything buffered so far.
// It must not block, since the caller's datagram loop is shared by every channel of
// the conversation.
func (m *channelsManager) addDanglingDatagramsQueue(id util.ChannelID, datagram []byte) {
	m.lock.Lock()
	defer m.lock.Unlock()
	// the channel may have been registered between the caller's lookup and this call
	if channel, ok := m.channels[id]; ok {
		channel.addDatagram(datagram)
		return
	}
	queue, ok := m.danglingDgramQueues[id]
	if !ok {
		// P4-01: a dangling queue is retained until a channel with this ID
		// registers or the conversation dies; the cap bounds the map. Only
		// brand-new IDs hit this branch: a legitimate late datagram extends
		// the queue it already has.
		if len(m.danglingDgramQueues) >= maxDanglingDatagramQueues {
			// F-15: evict the oldest queue instead of refusing the new ID —
			// refusing left the cap fail-closed, so junk IDs could silence
			// legitimate pre-registration datagrams for the conversation's
			// whole lifetime. The bound (and its memory) is unchanged.
			if len(m.danglingOrder) == 0 {
				log.Warn().Msgf("dangling datagram queues at cap with no eviction order, dropping datagram for unregistered channel %d", id)
				return
			}
			oldest := m.danglingOrder[0]
			m.danglingOrder = m.danglingOrder[1:]
			delete(m.danglingDgramQueues, oldest)
			log.Warn().Msgf("evicted dangling datagram queue for unregistered channel %d", oldest)
		}
		queue = util.NewDatagramsQueue(danglingDatagramQueueSize)
		m.danglingDgramQueues[id] = queue
		m.danglingOrder = append(m.danglingOrder, id)
	}
	if !queue.Add(datagram) {
		log.Warn().Msgf("dangling datagram queue for channel %d is full, dropping datagram", id)
	}
}

func (m *channelsManager) getChannel(id util.ChannelID) (Channel, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	channel, ok := m.channels[id]
	return channel, ok
}

func (m *channelsManager) removeChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.channels, util.ChannelID(channel.ChannelID()))
}

func (m *channelsManager) onChannelClose(channel Channel) {
	m.removeChannel(channel)
}

// removeChannelID removes id from the FIFO eviction order; the slice is small
// (bounded by maxDanglingDatagramQueues), so a linear scan under the manager
// mutex is fine.
func removeChannelID(ids []util.ChannelID, id util.ChannelID) []util.ChannelID {
	for i, candidate := range ids {
		if candidate == id {
			return append(ids[:i], ids[i+1:]...)
		}
	}
	return ids
}
