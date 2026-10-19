package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/statetrack/statetrack/server/internal/storage"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// Cross-origin is allowed for the local web console.
	CheckOrigin: func(*http.Request) bool { return true },
}

// wsClient is one connected browser.
type wsClient struct {
	conn *websocket.Conn
	send chan []byte
	done chan struct{}
}

// Hub fans out newly ingested events to connected WebSocket clients.
type Hub struct {
	mu      sync.Mutex
	clients map[*wsClient]struct{}
	logger  *slog.Logger
}

// NewHub builds an empty hub.
func NewHub(logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{clients: make(map[*wsClient]struct{}), logger: logger}
}

// Publish broadcasts a normalized event to every client. Slow clients are
// dropped rather than blocking ingestion.
func (h *Hub) Publish(n storage.Notification) {
	payload, err := json.Marshal(map[string]any{"type": "event", "event": n})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- payload:
		default:
			h.logger.Warn("websocket client too slow; dropping event", "event", n.ID)
		}
	}
}

func (h *Hub) add(c *wsClient) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *wsClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// ServeWS upgrades the connection and streams events until it closes.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Debug("websocket upgrade failed", "err", err)
		return
	}
	c := &wsClient{conn: conn, send: make(chan []byte, 64), done: make(chan struct{})}
	h.add(c)

	go c.writePump()
	c.readPump()

	// Client disconnected: stop the writer and drop it from the fan-out.
	h.remove(c)
	close(c.done)
	_ = conn.Close()
}

func (c *wsClient) writePump() {
	for {
		select {
		case msg := <-c.send:
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *wsClient) readPump() {
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}
