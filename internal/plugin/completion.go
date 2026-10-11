package plugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	t "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator/builtin"
)

type completion struct {
	provider, model string
	native          t.Format
	request, body   []byte
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func prepare(req request) (completion, error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(req.Payload, &source); err != nil || source == nil {
		return completion{}, fail(400, "Completion payload must be a JSON object")
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(source["messages"], &messages); err != nil || messages == nil {
		return completion{}, fail(400, "messages must be an array")
	}
	if req.SourceFormat != "" && req.SourceFormat != "openai" && req.SourceFormat != "chat-completions" {
		return completion{}, fail(400, "CPA must translate input to chat-completions")
	}
	model := strings.TrimPrefix(req.Model, "zed/")
	if model == "" {
		json.Unmarshal(source["model"], &model)
		model = strings.TrimPrefix(model, "zed/")
	}
	if strings.TrimSpace(model) == "" {
		return completion{}, fail(400, "A model is required")
	}
	provider := ""
	if before, after, ok := strings.Cut(model, "/"); ok {
		provider, model = before, after
	}
	if provider == "" {
		switch {
		case strings.HasPrefix(model, "claude-"):
			provider = "anthropic"
		case strings.HasPrefix(model, "gpt-"), strings.HasPrefix(model, "o1"), strings.HasPrefix(model, "o3"), strings.HasPrefix(model, "o4"):
			provider = "open_ai"
		case strings.HasPrefix(model, "gemini-"):
			provider = "google"
		case strings.HasPrefix(model, "grok-"):
			provider = "x_ai"
		default:
			return completion{}, fail(400, "Unknown Zed model: use an explicit upstream provider prefix")
		}
	}
	native := map[string]t.Format{"anthropic": t.FormatClaude, "open_ai": t.FormatCodex, "google": t.FormatGemini, "x_ai": t.FormatOpenAI}[provider]
	if native == "" || model == "" {
		return completion{}, fail(400, "Unsupported Zed upstream provider or empty model")
	}
	if native != t.FormatOpenAI && (!t.HasRequestTransformer(t.FormatOpenAI, native) || !t.HasStreamResponseTransformer(t.FormatOpenAI, native) || !t.HasNonStreamResponseTransformer(t.FormatOpenAI, native)) {
		return completion{}, fail(501, "CPA lacks a translator for the selected Zed model")
	}
	raw := t.TranslateRequest(t.FormatOpenAI, native, model, req.Payload, req.Stream)
	var upstream map[string]any
	if err := json.Unmarshal(raw, &upstream); err != nil || upstream == nil {
		return completion{}, fail(400, "Could not translate the completion request")
	}
	upstream["model"] = model
	if provider == "google" {
		upstream["model"] = "models/" + model
	} else {
		upstream["stream"] = req.Stream
	}
	if provider == "anthropic" {
		if _, ok := source["max_tokens"]; !ok {
			if _, ok = source["max_completion_tokens"]; !ok {
				upstream["max_tokens"] = 8192
			}
		}
	}
	if provider == "open_ai" {
		for _, key := range []string{"temperature", "top_p", "max_output_tokens"} {
			if value, ok := source[key]; ok {
				var v any
				json.Unmarshal(value, &v)
				upstream[key] = v
			}
		}
		for _, key := range []string{"max_tokens", "max_completion_tokens"} {
			if value, ok := source[key]; ok {
				var v any
				json.Unmarshal(value, &v)
				upstream["max_output_tokens"] = v
			}
		}
		// Codex's default reasoning setting is specific to Codex; Zed uses the model default.
		if _, ok := source["reasoning_effort"]; !ok {
			delete(upstream, "reasoning")
		}
	}
	nativeRequest, err := json.Marshal(upstream)
	if err != nil {
		return completion{}, err
	}
	body, err := json.Marshal(map[string]any{"thread_id": uuid(), "prompt_id": uuid(), "intent": "user_prompt", "provider": provider, "model": model, "provider_request": upstream})
	return completion{provider, model, native, nativeRequest, body}, err
}

func eventJSON(line []byte) ([]byte, error) {
	line = bytes.TrimSpace(line)
	if bytes.HasPrefix(line, []byte("data:")) {
		line = bytes.TrimSpace(line[5:])
	}
	if len(line) == 0 || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte(":")) || bytes.Equal(line, []byte("[DONE]")) {
		return nil, nil
	}
	if !json.Valid(line) {
		return nil, fail(502, "Zed returned malformed completion data")
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(line, &data) != nil || data == nil {
		return nil, fail(502, "Zed returned a non-object completion event")
	}
	var kind string
	json.Unmarshal(data["type"], &kind)
	if kind == "error" || kind == "response.failed" || data["error"] != nil && string(data["error"]) != "null" {
		return nil, fail(502, "Zed returned an upstream completion error")
	}
	return line, nil
}

func (a *App) execute(req request) (pluginapi.ExecutorResponse, error) {
	req.Stream = false
	c, err := prepare(req)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	if len(req.Metadata) == 0 {
		req.Metadata = req.AuthMetadata
	}
	resp, err := a.cloud(req, "POST", "/completions", c.body)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	var lines [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(resp.Body))
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)
	for scanner.Scan() {
		line, err := eventJSON(scanner.Bytes())
		if err != nil {
			return pluginapi.ExecutorResponse{}, err
		}
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	if err = scanner.Err(); err != nil {
		return pluginapi.ExecutorResponse{}, fail(502, "Zed completion event exceeds the size limit")
	}
	if len(lines) == 0 {
		return pluginapi.ExecutorResponse{}, fail(502, "Zed returned an empty completion")
	}
	var native []byte
	switch c.native {
	case t.FormatClaude:
		var sse bytes.Buffer
		ended := false
		for _, line := range lines {
			var e struct{ Type string }
			json.Unmarshal(line, &e)
			if e.Type == "message_stop" {
				ended = true
			}
			sse.WriteString("data: ")
			sse.Write(line)
			sse.WriteByte('\n')
		}
		if !ended {
			return pluginapi.ExecutorResponse{}, fail(502, "Zed Claude response ended before message_stop")
		}
		native = sse.Bytes()
	case t.FormatCodex:
		for _, line := range lines {
			var e struct{ Type string }
			json.Unmarshal(line, &e)
			if e.Type == "response.completed" || e.Type == "response.incomplete" {
				native = line
			}
		}
		if len(native) == 0 {
			return pluginapi.ExecutorResponse{}, fail(502, "Zed OpenAI response ended before completion")
		}
	default:
		if len(lines) == 1 {
			native = lines[0]
		} else {
			return collectCompletion(req, c, lines)
		}
	}
	var state any
	output := t.TranslateNonStream(context.Background(), c.native, t.FormatOpenAI, req.Model, req.Payload, c.request, native, &state)
	var result map[string]any
	if json.Unmarshal(output, &result) != nil || result["choices"] == nil {
		return pluginapi.ExecutorResponse{}, fail(502, "Invalid translated Zed completion")
	}
	result["model"] = req.Model
	output, err = json.Marshal(result)
	return pluginapi.ExecutorResponse{Payload: output, Headers: httpJSONHeaders()}, err
}

func httpJSONHeaders() map[string][]string {
	return map[string][]string{"Content-Type": {"application/json"}}
}

func collectCompletion(req request, c completion, lines [][]byte) (pluginapi.ExecutorResponse, error) {
	result := map[string]any{"object": "chat.completion", "model": req.Model}
	choices := map[int]map[string]any{}
	tools := map[int]map[int]map[string]any{}
	var state any
	ended := false
	for _, line := range lines {
		frames := [][]byte{line}
		if c.native != t.FormatOpenAI {
			frames = t.TranslateStream(context.Background(), c.native, t.FormatOpenAI, req.Model, req.Payload, c.request, append([]byte("data: "), line...), &state)
		}
		for _, frame := range frames {
			var chunk struct {
				ID      string
				Created int64
				Usage   json.RawMessage
				Choices []struct {
					Index        int
					Delta        map[string]any
					FinishReason *string `json:"finish_reason"`
				}
			}
			if err := json.Unmarshal(frame, &chunk); err != nil {
				return pluginapi.ExecutorResponse{}, fail(502, "Invalid translated completion chunk")
			}
			if chunk.ID != "" {
				result["id"] = chunk.ID
			}
			if chunk.Created != 0 {
				result["created"] = chunk.Created
			}
			if len(chunk.Usage) > 0 && string(chunk.Usage) != "null" {
				result["usage"] = chunk.Usage
			}
			for _, choice := range chunk.Choices {
				out := choices[choice.Index]
				if out == nil {
					out = map[string]any{"index": choice.Index, "message": map[string]any{"role": "assistant", "content": ""}}
					choices[choice.Index] = out
					tools[choice.Index] = map[int]map[string]any{}
				}
				message := out["message"].(map[string]any)
				for _, key := range []string{"content", "reasoning_content"} {
					if value, ok := choice.Delta[key].(string); ok {
						existing, _ := message[key].(string)
						message[key] = existing + value
					}
				}
				calls, _ := choice.Delta["tool_calls"].([]any)
				for _, value := range calls {
					call, ok := value.(map[string]any)
					if !ok {
						continue
					}
					index, _ := call["index"].(float64)
					tool := tools[choice.Index][int(index)]
					if tool == nil {
						tool = map[string]any{"type": "function", "function": map[string]any{"name": "", "arguments": ""}}
						tools[choice.Index][int(index)] = tool
					}
					if id, ok := call["id"].(string); ok {
						tool["id"] = id
					}
					if fn, ok := call["function"].(map[string]any); ok {
						target := tool["function"].(map[string]any)
						for _, key := range []string{"name", "arguments"} {
							if value, ok := fn[key].(string); ok {
								target[key] = target[key].(string) + value
							}
						}
					}
				}
				if choice.FinishReason != nil {
					out["finish_reason"] = *choice.FinishReason
					ended = true
				}
			}
		}
	}
	if !ended {
		return pluginapi.ExecutorResponse{}, fail(502, "Zed completion ended before a finish reason")
	}
	// Stable choice/tool order follows the indexes supplied by the upstream API.
	indexes := make([]int, 0, len(choices))
	for index := range choices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	output := make([]any, 0, len(indexes))
	for _, index := range indexes {
		out := choices[index]
		toolIndexes := make([]int, 0, len(tools[index]))
		for i := range tools[index] {
			toolIndexes = append(toolIndexes, i)
		}
		sort.Ints(toolIndexes)
		if len(toolIndexes) > 0 {
			calls := make([]any, 0, len(toolIndexes))
			for _, i := range toolIndexes {
				calls = append(calls, tools[index][i])
			}
			out["message"].(map[string]any)["tool_calls"] = calls
		}
		output = append(output, out)
	}
	result["choices"] = output
	raw, err := json.Marshal(result)
	return pluginapi.ExecutorResponse{Payload: raw, Headers: httpJSONHeaders()}, err
}
