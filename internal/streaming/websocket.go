package streaming

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"orbguard-lab/pkg/logger"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins for mobile apps
		return true
	},
}

// WebSocketHub manages WebSocket connections
type WebSocketHub struct {
	publisher *NATSPublisher
	logger    *logger.Logger

	mu      sync.RWMutex
	clients map[*WebSocketClient]bool

	// Broadcast channel for events without NATS
	broadcast chan *ThreatEvent
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	hub          *WebSocketHub
	conn         *websocket.Conn
	send         chan []byte
	subscription *Subscription
	logger       *logger.Logger
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub(publisher *NATSPublisher, log *logger.Logger) *WebSocketHub {
	return &WebSocketHub{
		publisher: publisher,
		logger:    log.WithComponent("websocket-hub"),
		clients:   make(map[*WebSocketClient]bool),
		broadcast: make(chan *ThreatEvent, 256),
	}
}

// Run starts the hub's main loop
func (h *WebSocketHub) Run(ctx context.Context) {
	h.logger.Info().Msg("WebSocket hub started")

	for {
		select {
		case <-ctx.Done():
			h.logger.Info().Msg("WebSocket hub stopping")
			h.closeAllClients()
			return
		case event := <-h.broadcast:
			h.broadcastEvent(event)
		}
	}
}

// BroadcastEvent sends an event to all matching clients
func (h *WebSocketHub) BroadcastEvent(event *ThreatEvent) {
	select {
	case h.broadcast <- event:
	default:
		h.logger.Warn().Msg("broadcast channel full, dropping event")
	}
}

// broadcastEvent sends an event to all matching clients
func (h *WebSocketHub) broadcastEvent(event *ThreatEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to marshal event for broadcast")
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if client.subscription == nil || client.subscription.Matches(event) {
			select {
			case client.send <- data:
			default:
				// Client buffer full, skip
			}
		}
	}
}

// closeAllClients closes all connected clients
func (h *WebSocketHub) closeAllClients() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.clients {
		close(client.send)
		delete(h.clients, client)
	}
}

// registerClient adds a client to the hub
func (h *WebSocketHub) registerClient(client *WebSocketClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client] = true
	h.logger.Info().Int("clients", len(h.clients)).Msg("client connected")
}

// unregisterClient removes a client from the hub
func (h *WebSocketHub) unregisterClient(client *WebSocketClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
		h.logger.Info().Int("clients", len(h.clients)).Msg("client disconnected")
	}
}

// ClientCount returns the number of connected clients
func (h *WebSocketHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ServeWebSocket handles WebSocket connections
func (h *WebSocketHub) ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to upgrade connection")
		return
	}

	client := &WebSocketClient{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 256),
		logger: h.logger,
	}

	h.registerClient(client)

	// Start client goroutines
	go client.writePump()
	go client.readPump()
}

// readPump reads messages from the client
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregisterClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(64 * 1024) // 64KB max message size
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.logger.Warn().Err(err).Msg("websocket read error")
			}
			break
		}

		// Handle subscription update
		var sub Subscription
		if err := json.Unmarshal(message, &sub); err == nil {
			c.subscription = &sub
			c.logger.Debug().Msg("subscription updated")
		}
	}
}

// writePump writes messages to the client
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Batch pending messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte("\n"))
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// WebSocketMessage is a message sent to/from WebSocket clients
type WebSocketMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}
