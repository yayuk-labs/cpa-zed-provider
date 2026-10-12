package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	t "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type upstreamStream struct {
	Status  int         `json:"status_code"`
	Headers http.Header `json:"headers"`
	ID      string      `json:"stream_id"`
}

func (a *App) executeStream(req request) (any, error) {
	if req.StreamID == "" {
		return nil, fail(400, "CPA stream_id is required")
	}
	req.Stream = true
	c, err := a.prepare(req)
	if err != nil {
		return nil, err
	}
	credential, err := credentialFrom(req.StorageJSON, req.AuthMetadata)
	if err != nil {
		return nil, err
	}
	var resp upstreamStream
	for attempt := 0; attempt < 2; attempt++ {
		value, err := a.llmToken(credential, req.CallbackID, attempt == 1)
		if err != nil {
			return nil, err
		}
		cfg := a.settings()
		err = a.host("host.http.do_stream", map[string]any{"method": "POST", "url": strings.TrimRight(cfg.BaseURL, "/") + "/completions", "headers": zedHeaders(value, cfg.ZedVersion), "body": c.body, "host_callback_id": req.CallbackID}, &resp)
		if err != nil {
			return nil, err
		}
		if resp.Status >= 200 && resp.Status < 300 {
			break
		}
		var body []byte
		if resp.ID != "" {
			// Bound rejected response reads; never forward raw upstream bodies.
			for reads := 0; reads < 16 && len(body) <= 64*1024; reads++ {
				var chunk struct {
					Payload []byte `json:"payload"`
					Done    bool   `json:"done"`
					Error   string `json:"error"`
				}
				if a.host("host.http.stream_read", map[string]string{"stream_id": resp.ID}, &chunk) != nil {
					break
				}
				body = append(body, chunk.Payload...)
				if chunk.Done || chunk.Error != "" {
					break
				}
			}
			a.host("host.http.stream_close", map[string]string{"stream_id": resp.ID}, nil)
		}
		if attempt == 0 && stale(resp.Status, resp.Headers) {
			continue
		}
		return nil, completionError(resp.Status, "streaming completion", body, credential.secret, value)
	}
	if resp.ID == "" {
		return nil, fail(502, "CPA did not return an upstream stream ID")
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.host("host.http.stream_close", map[string]string{"stream_id": resp.ID}, nil)
		return nil, fail(503, "Zed plugin is shutting down")
	}
	a.streams[resp.ID] = req.StreamID
	a.workers.Add(1)
	a.mu.Unlock()
	go a.pumpStream(req, c, resp.ID)
	return map[string]any{"headers": http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-cache"}}}, nil
}

func (a *App) pumpStream(req request, c completion, upstreamID string) {
	defer a.workers.Done()
	var streamErr error
	defer func() {
		a.host("host.http.stream_close", map[string]string{"stream_id": upstreamID}, nil)
		closeReq := map[string]string{"stream_id": req.StreamID}
		if streamErr != nil {
			closeReq["error"] = streamErr.Error()
		}
		a.host("host.stream.close", closeReq, nil)
		a.mu.Lock()
		delete(a.streams, upstreamID)
		a.mu.Unlock()
	}()
	var state any
	var buffer []byte
	ended := false
	terminal := false
	emit := func(payload []byte) error {
		return a.host("host.stream.emit", map[string]any{"stream_id": req.StreamID, "payload": payload}, nil)
	}
	process := func(raw []byte) error {
		line, done, err := eventJSON(raw)
		if err != nil {
			return err
		}
		terminal = done
		if len(line) == 0 {
			return nil
		}
		var event struct {
			Type    string
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
			}
			Candidates []struct {
				FinishReason string `json:"finishReason"`
			}
		}
		json.Unmarshal(line, &event)
		if event.Type == "message_stop" || event.Type == "response.completed" || event.Type == "response.incomplete" {
			ended = true
		}
		for _, choice := range event.Choices {
			if choice.FinishReason != nil {
				ended = true
			}
		}
		for _, candidate := range event.Candidates {
			if candidate.FinishReason != "" {
				ended = true
			}
		}
		frames := [][]byte{line}
		if c.native != t.FormatOpenAI {
			frames = t.TranslateStream(context.Background(), c.native, t.FormatOpenAI, req.Model, req.Payload, c.request, append([]byte("data: "), line...), &state)
		}
		for _, frame := range frames {
			frame = bytes.TrimSpace(frame)
			if len(frame) == 0 || bytes.Equal(frame, []byte("[DONE]")) {
				continue
			}
			if bytes.HasPrefix(frame, []byte("data:")) {
				frame = bytes.TrimSpace(frame[5:])
			}
			if !json.Valid(frame) {
				return fail(502, "Invalid translated Zed stream chunk")
			}
			if err = emit(append(append([]byte("data: "), frame...), []byte("\n\n")...)); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		var chunk struct {
			Payload []byte `json:"payload"`
			Done    bool   `json:"done"`
			Error   string `json:"error"`
		}
		if err := a.host("host.http.stream_read", map[string]string{"stream_id": upstreamID}, &chunk); err != nil {
			streamErr = err
			return
		}
		buffer = append(buffer, chunk.Payload...)
		for {
			index := bytes.IndexByte(buffer, '\n')
			if index < 0 {
				break
			}
			if err := process(buffer[:index]); err != nil {
				streamErr = err
				return
			}
			if terminal {
				streamErr = emit([]byte("data: [DONE]\n\n"))
				return
			}
			buffer = buffer[index+1:]
		}
		if len(buffer) > 16*1024*1024 {
			streamErr = fail(502, "Zed stream event exceeds the size limit")
			return
		}
		if chunk.Error != "" {
			streamErr = fail(502, "Zed upstream stream failed")
			return
		}
		if chunk.Done {
			if err := process(buffer); err != nil {
				streamErr = err
				return
			}
			if !ended && !terminal {
				streamErr = fail(502, "Zed stream ended before a completion event")
				return
			}
			streamErr = emit([]byte("data: [DONE]\n\n"))
			return
		}
	}
}
