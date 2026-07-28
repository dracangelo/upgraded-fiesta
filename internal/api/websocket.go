package api

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"enumscan/internal/models"
)

const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type WSConnection struct {
	conn net.Conn
	mu   sync.Mutex
}

func (w *WSConnection) WriteTextFrame(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	length := len(data)
	var header []byte

	// Opcode 0x1 (Text Frame), FIN bit set (0x80) -> 0x81
	header = append(header, 0x81)

	if length <= 125 {
		header = append(header, byte(length))
	} else if length <= 65535 {
		header = append(header, 126, byte(length>>8), byte(length&0xFF))
	} else {
		header = append(header, 127,
			byte((length>>56)&0xFF), byte((length>>48)&0xFF),
			byte((length>>40)&0xFF), byte((length>>32)&0xFF),
			byte((length>>24)&0xFF), byte((length>>16)&0xFF),
			byte((length>>8)&0xFF), byte(length&0xFF),
		)
	}

	if _, err := w.conn.Write(header); err != nil {
		return err
	}
	_, err := w.conn.Write(data)
	return err
}

func (s *Server) upgradeToWebSocket(w http.ResponseWriter, r *http.Request) (*WSConnection, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("invalid upgrade header")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	// Calculate Accept Key according to RFC 6455
	h := sha1.New()
	h.Write([]byte(key + magicGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("webserver does not support hijacking")
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	// Write HTTP 101 Switching Protocols response
	response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey)

	if _, err := bufrw.WriteString(response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &WSConnection{conn: conn}, nil
}

func (s *Server) handleWebSocketEvents(w http.ResponseWriter, r *http.Request) {
	// Upgrade to real WebSocket if Upgrade header present, else SSE fallback
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		ws, err := s.upgradeToWebSocket(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer ws.conn.Close()

		ch := make(chan models.Event, 50)
		s.mu.Lock()
		s.wsClients[ch] = true
		s.mu.Unlock()

		defer func() {
			s.mu.Lock()
			delete(s.wsClients, ch)
			s.mu.Unlock()
			close(ch)
		}()

		// Send initial handshake frame
		_ = ws.WriteTextFrame([]byte(`{"type":"connection_established"}`))

		for {
			select {
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, err := json.Marshal(evt)
				if err == nil {
					if err := ws.WriteTextFrame(data); err != nil {
						return
					}
				}
			case <-r.Context().Done():
				return
			}
		}
	}

	// SSE Fallback
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan models.Event, 50)
	s.mu.Lock()
	s.wsClients[ch] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.wsClients, ch)
		s.mu.Unlock()
		close(ch)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(evt)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
