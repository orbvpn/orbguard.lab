package handlers

import (
	"encoding/json"
	"net/http"

	"orbguard-lab/internal/streaming"
	"orbguard-lab/pkg/logger"
)

// StreamingHandler handles real-time streaming endpoints
type StreamingHandler struct {
	wsHub    *streaming.WebSocketHub
	eventBus *streaming.EventBus
	logger   *logger.Logger
}

// NewStreamingHandler creates a new streaming handler
func NewStreamingHandler(wsHub *streaming.WebSocketHub, eventBus *streaming.EventBus, log *logger.Logger) *StreamingHandler {
	return &StreamingHandler{
		wsHub:    wsHub,
		eventBus: eventBus,
		logger:   log.WithComponent("streaming-handler"),
	}
}

// HandleWebSocket handles WebSocket connections for real-time threat updates
func (h *StreamingHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	if h.wsHub == nil {
		http.Error(w, "WebSocket streaming not available", http.StatusServiceUnavailable)
		return
	}

	h.logger.Debug().
		Str("remote_addr", r.RemoteAddr).
		Str("user_agent", r.UserAgent()).
		Msg("WebSocket connection request")

	h.wsHub.ServeWebSocket(w, r)
}

// GetStats returns streaming statistics
func (h *StreamingHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"websocket_clients":  0,
		"event_bus_subscribers": 0,
	}

	if h.wsHub != nil {
		stats["websocket_clients"] = h.wsHub.ClientCount()
	}

	if h.eventBus != nil {
		stats["event_bus_subscribers"] = h.eventBus.SubscriberCount()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
