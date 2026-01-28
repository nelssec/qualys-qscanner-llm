package api

import (
	"encoding/json"
	"net/http"

	"github.com/nelssec/qualys-qscanner-llm/internal/agent"
	"github.com/google/uuid"
)

type ChatRequest struct {
	ConversationID string `json:"conversation_id,omitempty"`
	Message        string `json:"message"`
}

type ChatResponse struct {
	ConversationID string `json:"conversation_id"`
	Response       string `json:"response"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		s.writeError(w, "message is required", http.StatusBadRequest)
		return
	}

	convID := req.ConversationID
	var history []agent.Message

	if convID == "" {
		convID = uuid.New().String()
		s.store.Create(convID)
	} else {
		conv := s.store.Get(convID)
		if conv != nil {
			history = conv.Messages
		} else {
			s.store.Create(convID)
		}
	}

	response, newHistory, err := s.agent.Chat(r.Context(), req.Message, history)
	if err != nil {
		s.logger.Error().Err(err).Msg("chat error")
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.store.Update(convID, newHistory)

	s.writeJSON(w, ChatResponse{
		ConversationID: convID,
		Response:       response,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
