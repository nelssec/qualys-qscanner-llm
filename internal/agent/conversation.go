package agent

import (
	"sync"
	"time"
)

type Conversation struct {
	ID        string    `json:"id"`
	Messages  []Message `json:"messages"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ConversationStore struct {
	conversations map[string]*Conversation
	mu            sync.RWMutex
}

func NewConversationStore() *ConversationStore {
	return &ConversationStore{
		conversations: make(map[string]*Conversation),
	}
}

func (s *ConversationStore) Create(id string) *Conversation {
	s.mu.Lock()
	defer s.mu.Unlock()

	conv := &Conversation{
		ID:        id,
		Messages:  make([]Message, 0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.conversations[id] = conv
	return conv
}

func (s *ConversationStore) Get(id string) *Conversation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.conversations[id]
}

func (s *ConversationStore) Update(id string, messages []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if conv, ok := s.conversations[id]; ok {
		conv.Messages = messages
		conv.UpdatedAt = time.Now()
	}
}

func (s *ConversationStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.conversations, id)
}

func (s *ConversationStore) List() []*Conversation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*Conversation, 0, len(s.conversations))
	for _, conv := range s.conversations {
		list = append(list, conv)
	}
	return list
}

func (s *ConversationStore) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, conv := range s.conversations {
		if conv.UpdatedAt.Before(cutoff) {
			delete(s.conversations, id)
		}
	}
}
