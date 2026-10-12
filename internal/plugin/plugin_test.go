package plugin_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"cpa-zed-provider/internal/plugin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func rpc(t *testing.T, app *plugin.App, method string, req any, out any) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response, err := app.HandleMethod(method, raw)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  any             `json:"error"`
	}
	if err = json.Unmarshal(response, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("%s: %s", method, response)
	}
	if out != nil {
		if err = json.Unmarshal(envelope.Result, out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBrowserLoginDecryptsCallbackAndRefreshesCredential(t *testing.T) {
	for _, tc := range []struct{ existing, remote bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("existing=%t/remote=%t", tc.existing, tc.remote), func(t *testing.T) {
			existing := tc.existing
			app := plugin.NewApp()
			defer app.Shutdown()
			app.SetHostCaller(func(method string, payload any) (json.RawMessage, error) {
				switch method {
				case "host.auth.list":
					if existing {
						return json.RawMessage(`{"files":[{"id":"stable-auth","auth_index":"account-42","name":"custom.json","provider":"zed"}]}`), nil
					}
					return json.RawMessage(`{"files":[]}`), nil
				case "host.auth.get":
					return json.RawMessage(`{"name":"custom.json","json":{"type":"zed","user_id":"42","credential_json":"old-dummy","prefix":"work","disabled":true,"organization_id":"org-personal","note":"keep me"}}`), nil
				}
				return nil, fmt.Errorf("unexpected host callback %s", method)
			})
			var login pluginapi.AuthLoginStartResponse
			rpc(t, app, "auth.login.start", pluginapi.AuthLoginStartRequest{Provider: "zed"}, &login)
			link, err := url.Parse(login.URL)
			if err != nil {
				t.Fatal(err)
			}
			if link.Host != "zed.dev" || link.Path != "/native_app_signin" || login.State == "" || time.Until(login.ExpiresAt) > 10*time.Minute {
				t.Fatalf("invalid login response: %+v", login)
			}
			der, err := base64.RawURLEncoding.DecodeString(link.Query().Get("native_app_public_key"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := x509.ParsePKCS1PublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			var poll pluginapi.AuthLoginPollResponse
			rpc(t, app, "auth.login.poll", pluginapi.AuthLoginPollRequest{Provider: "zed", State: login.State}, &poll)
			if poll.Status != "pending" {
				t.Fatal("login did not start pending")
			}
			cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, []byte("dummy-credential"), nil)
			if err != nil {
				t.Fatal(err)
			}
			callback := "http://127.0.0.1:" + link.Query().Get("native_app_port") + "/?" + url.Values{"user_id": {"42"}, "access_token": {base64.URLEncoding.EncodeToString(cipher)}}.Encode()
			submit := func(callbackURL, state string) int {
				if tc.remote {
					body, _ := json.Marshal(map[string]string{"state": state, "redirect_url": callbackURL})
					var result pluginapi.ManagementResponse
					rpc(t, app, "management.handle", pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/plugins/zed/callback", Body: body}, &result)
					return result.StatusCode
				}
				client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				response, err := client.Get(callbackURL)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode == 307 && response.Header.Get("Location") != "https://zed.dev/native_app_signin_succeeded" {
					t.Fatal("wrong success redirect")
				}
				return response.StatusCode
			}
			if tc.remote {
				for _, invalid := range []string{
					strings.Replace(callback, "127.0.0.1", "example.com", 1),
					strings.Replace(callback, "/?", "/other?", 1),
					strings.Replace(callback, "http://", "https://", 1),
					strings.Replace(callback, "http://", "http://other@", 1),
					callback + "#fragment",
					"http://127.0.0.1:1/?user_id=42&access_token=invalid",
					"http://127.0.0.1:" + link.Query().Get("native_app_port") + "/?user_id=42&access_token=invalid",
				} {
					if status := submit(invalid, login.State); status != 400 {
						t.Fatalf("invalid callback accepted: %d", status)
					}
				}
				if status := submit(callback, "unknown-state"); status != 410 {
					t.Fatalf("unknown session accepted: %d", status)
				}
			}
			expectedStatus := 307
			if tc.remote {
				expectedStatus = 200
			}
			if status := submit(callback, login.State); status != expectedStatus {
				t.Fatalf("callback status %d, want %d", status, expectedStatus)
			}
			if status := submit(callback, login.State); status != 409 {
				t.Fatalf("callback replay accepted: %d", status)
			}
			rpc(t, app, "auth.login.poll", pluginapi.AuthLoginPollRequest{Provider: "zed", State: login.State}, &poll)
			expected := "zed-login-42.json"
			if existing {
				expected = "custom.json"
			}
			if poll.Status != "success" || poll.Auth.FileName != expected || poll.Auth.Metadata["credential_json"] != "dummy-credential" {
				t.Fatalf("incorrect completed auth: %+v", poll)
			}
			if existing && (poll.Auth.ID != "stable-auth" || poll.Auth.Prefix != "work" || !poll.Auth.Disabled || poll.Auth.Metadata["note"] != "keep me") {
				t.Fatal("relogin discarded existing account settings")
			}
			app.SetHostCaller(func(method string, payload any) (json.RawMessage, error) {
				return json.RawMessage(`{"StatusCode":200,"Body":"eyJ0b2tlbiI6Im5ldy10b2tlbiJ9"}`), nil
			})
			var refreshed pluginapi.AuthRefreshResponse
			rpc(t, app, "auth.refresh", pluginapi.AuthRefreshRequest{AuthID: poll.Auth.ID, AuthProvider: "zed", StorageJSON: poll.Auth.StorageJSON, Metadata: poll.Auth.Metadata}, &refreshed)
			if refreshed.Auth.ID != poll.Auth.ID || refreshed.Auth.Metadata["credential_json"] != "dummy-credential" || time.Until(refreshed.NextRefreshAfter) < 58*time.Minute {
				t.Fatal("refresh lost credential or returned wrong schedule")
			}
		})
	}
}

func TestStreamsFragmentedEventsBeforeUpstreamFinishes(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/client/llm_tokens" {
			io.WriteString(w, `{"token":"dummy-token"}`)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, fragment := range []string{`{"type":"message_start","message":{"id":"msg_stream","model":"claude-sonnet-4-5","usage":{"input_tokens":2}}}` + "\n", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"H`, "éllo\"}}\n"} {
			io.WriteString(w, fragment)
			w.(http.Flusher).Flush()
		}
		<-release
		io.WriteString(w, `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`+"\n"+`{"type":"message_stop"}`)
	}))
	defer func() { finish(); server.Close() }()
	app := testApp(t, server.URL)
	// Real HTTP at the boundary; callback machinery models CPA's stream bridge.
	var upstream *http.Response
	chunks := make(chan []byte, 16)
	done := make(chan struct{})
	app.SetHostCaller(func(method string, payload any) (json.RawMessage, error) {
		raw, _ := json.Marshal(payload)
		switch method {
		case "host.http.do":
			return json.RawMessage(`{"StatusCode":200,"Body":"eyJ0b2tlbiI6ImR1bW15LXRva2VuIn0="}`), nil
		case "host.http.do_stream":
			var req struct {
				Method, URL string
				Headers     http.Header
				Body        []byte
				CallbackID  string `json:"host_callback_id"`
			}
			json.Unmarshal(raw, &req)
			if req.CallbackID != "request-1" {
				return nil, fmt.Errorf("missing callback context")
			}
			r, _ := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
			r.Header = req.Headers
			var err error
			upstream, err = http.DefaultClient.Do(r)
			if err != nil {
				return nil, err
			}
			return json.RawMessage(`{"status_code":200,"stream_id":"upstream-1"}`), nil
		case "host.http.stream_read":
			buf := make([]byte, 17)
			n, err := upstream.Body.Read(buf)
			return json.Marshal(map[string]any{"payload": buf[:n], "done": err == io.EOF})
		case "host.http.stream_close":
			upstream.Body.Close()
			return json.RawMessage(`{}`), nil
		case "host.stream.emit":
			var req struct{ Payload []byte }
			json.Unmarshal(raw, &req)
			chunks <- req.Payload
			return json.RawMessage(`{}`), nil
		case "host.stream.close":
			close(done)
			return json.RawMessage(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected callback %s", method)
		}
	})
	req := completionRequest("zed/claude-sonnet-4-5")
	req["Stream"] = true
	req["stream_id"] = "downstream-1"
	rpc(t, app, "executor.execute_stream", req, nil)
	var observed strings.Builder
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(observed.String(), "Héllo") {
		select {
		case chunk := <-chunks:
			observed.Write(chunk)
		case <-deadline.C:
			t.Fatal("stream buffered until completion or lost split UTF-8")
		}
	}
	finish()
	select {
	case <-done:
	case <-deadline.C:
		t.Fatal("stream did not close")
	}
	for len(chunks) > 0 {
		observed.Write(<-chunks)
	}
	if !strings.Contains(observed.String(), "data: [DONE]\n\n") || !strings.Contains(observed.String(), `"completion_tokens":1`) {
		t.Fatalf("missing stream end or usage: %s", observed.String())
	}
}

func TestAccountDiscoversModelsAndRefreshesStaleToken(t *testing.T) {
	exchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/llm_tokens":
			if r.Method != "POST" || r.Header.Get("Authorization") != "42 dummy-credential" || r.Header.Get("X-Zed-System-Id") != "" {
				t.Error("incorrect credential exchange")
			}
			exchanges++
			fmt.Fprintf(w, `{"token":"token-%d"}`, exchanges)
		case "/models":
			if r.Header.Get("X-Zed-Version") != "0.222.4" {
				t.Error("missing Zed version")
			}
			if r.Header.Get("Authorization") == "Bearer token-1" {
				w.Header().Set("X-Zed-Expired-Token", "true")
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"models":[{"id":"claude-sonnet-4-5"},{"id":"open_ai/gpt-4.1"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	app := testApp(t, server.URL)
	var models pluginapi.ModelResponse
	req := map[string]any{"AuthID": "zed-test.json", "AuthProvider": "zed", "StorageJSON": []byte(`{"type":"zed","user_id":"42","credential_json":"dummy-credential"}`), "host_callback_id": "request-1"}
	rpc(t, app, "model.for_auth", req, &models)
	if exchanges != 2 || models.Provider != "zed" || len(models.Models) != 2 || models.Models[0].ID != "zed/claude-sonnet-4-5" || models.Models[1].ID != "zed/open_ai/gpt-4.1" {
		t.Fatalf("incorrect models or stale retry: %+v, exchanges=%d", models, exchanges)
	}
	rpc(t, app, "model.for_auth", req, &models)
	if exchanges != 2 {
		t.Fatal("valid LLM token was not cached")
	}
}

func testApp(t *testing.T, baseURL string) *plugin.App {
	t.Helper()
	app := plugin.NewApp()
	t.Cleanup(app.Shutdown)
	app.SetHostCaller(func(method string, payload any) (json.RawMessage, error) {
		if method != "host.http.do" {
			return nil, fmt.Errorf("unexpected callback %s", method)
		}
		raw, _ := json.Marshal(payload)
		var req struct {
			Method, URL string
			Headers     http.Header
			Body        []byte
			CallbackID  string `json:"host_callback_id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.CallbackID != "request-1" {
			return nil, fmt.Errorf("missing callback context")
		}
		r, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
		if err != nil {
			return nil, err
		}
		r.Header = req.Headers
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return json.Marshal(pluginapi.HTTPResponse{StatusCode: resp.StatusCode, Headers: resp.Header, Body: body})
	})
	rpc(t, app, "plugin.register", map[string]any{"config_yaml": []byte("base_url: " + baseURL)}, nil)
	return app
}

const claudeEvents = `{"type":"message_start","message":{"id":"msg_test","model":"claude-sonnet-4-5","usage":{"input_tokens":10,"cache_read_input_tokens":3}}}
{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}
{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Consider weather"}}
{"type":"content_block_stop","index":0}
{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_test","name":"weather","input":{}}}
{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Jakarta\"}"}}
{"type":"content_block_stop","index":1}
{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}
{"type":"message_stop"}`

func TestCompletionPreservesToolsReasoningAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/client/llm_tokens" {
			io.WriteString(w, `{"token":"dummy-llm-token"}`)
			return
		}
		if r.URL.Path != "/completions" {
			t.Error("unexpected completion path")
			w.WriteHeader(404)
			return
		}
		var body struct {
			Provider, Model, ThreadID, PromptID string
			Intent                              string
			Request                             map[string]any `json:"provider_request"`
		}
		// Verify Zed's native request at the external API boundary.
		var envelope map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			return
		}
		raw, _ := json.Marshal(envelope)
		json.Unmarshal(raw, &body)
		if body.Provider != "anthropic" || body.Model != "claude-sonnet-4-5" || body.Request["system"] == nil || body.Request["tools"] == nil || body.Request["max_tokens"] != float64(123) {
			t.Errorf("lost request fields: %s", raw)
		}
		if len(envelope["thread_id"]) != 38 || len(envelope["prompt_id"]) != 38 || body.Intent != "user_prompt" {
			t.Error("invalid Zed envelope")
		}
		io.WriteString(w, claudeEvents)
	}))
	defer server.Close()
	app := testApp(t, server.URL)
	var resp pluginapi.ExecutorResponse
	req := completionRequest("zed/claude-sonnet-4-5")
	rpc(t, app, "executor.execute", req, &resp)
	var body struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Reasoning string `json:"reasoning_content"`
				ToolCalls []struct {
					ID       string
					Function struct{ Name, Arguments string }
				} `json:"tool_calls"`
			}
		}
		Usage struct {
			Prompt, Completion, Total int `json:"-"`
		}
	}
	if err := json.Unmarshal(resp.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Choices) != 1 || body.Choices[0].FinishReason != "tool_calls" || body.Choices[0].Message.Reasoning != "Consider weather" || len(body.Choices[0].Message.ToolCalls) != 1 || body.Choices[0].Message.ToolCalls[0].Function.Arguments != `{"city":"Jakarta"}` {
		t.Fatalf("lost completion fields: %s", resp.Payload)
	}
	var usage struct {
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
			Total      int `json:"total_tokens"`
		}
	}
	json.Unmarshal(resp.Payload, &usage)
	if usage.Usage.Prompt != 13 || usage.Usage.Completion != 7 || usage.Usage.Total != 20 {
		t.Fatalf("incorrect usage: %s", resp.Payload)
	}
}

func completionRequest(model string) map[string]any {
	return map[string]any{"AuthID": "zed-test.json", "AuthProvider": "zed", "Model": model, "Format": "openai", "SourceFormat": "openai", "StorageJSON": []byte(`{"type":"zed","user_id":"42","credential_json":"dummy-credential"}`), "Payload": []byte(`{"model":"` + model + `","messages":[{"role":"system","content":"Helpful"},{"role":"user","content":"Weather?"}],"max_tokens":123,"tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]}`), "host_callback_id": "request-1"}
}

func TestOtherUpstreamProviders(t *testing.T) {
	for _, tc := range []struct{ model, provider, response string }{
		{"zed/open_ai/gpt-4.1", "open_ai", `{"type":"response.completed","response":{"id":"resp_test","model":"gpt-4.1","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello"}]}],"usage":{"input_tokens":4,"output_tokens":2,"total_tokens":6}}}`},
		{"zed/google/gemini-2.5-pro", "google", `{"candidates":[{"content":{"parts":[{"text":"Hel"}],"role":"model"}}]}` + "\n" + `{"candidates":[{"content":{"parts":[{"text":"lo"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":2,"totalTokenCount":6}}`},
		{"zed/x_ai/grok-3", "x_ai", `{"id":"chat_test","object":"chat.completion","model":"grok-3","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/client/llm_tokens" {
					io.WriteString(w, `{"token":"dummy-token"}`)
					return
				}
				var body struct {
					Provider string
					Request  map[string]any `json:"provider_request"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				if body.Provider != tc.provider {
					t.Errorf("wrong provider: %+v", body)
				}
				if tc.provider == "open_ai" && (body.Request["input"] == nil || body.Request["tools"] == nil || body.Request["max_output_tokens"] != float64(123)) {
					t.Errorf("lost Responses inputs: %+v", body.Request)
				}
				if tc.provider == "google" && body.Request["contents"] == nil {
					t.Error("Google received Chat Completions instead of native Gemini")
				}
				io.WriteString(w, tc.response)
			}))
			defer server.Close()
			app := testApp(t, server.URL)
			var resp pluginapi.ExecutorResponse
			rpc(t, app, "executor.execute", completionRequest(tc.model), &resp)
			var data struct {
				Model   string
				Choices []struct{ Message struct{ Content string } }
				Usage   struct {
					Total int `json:"total_tokens"`
				}
			}
			if err := json.Unmarshal(resp.Payload, &data); err != nil {
				t.Fatal(err)
			}
			if len(data.Choices) != 1 || data.Choices[0].Message.Content != "Hello" || data.Usage.Total != 6 || data.Model != tc.model {
				t.Fatalf("incorrect completion: %s", resp.Payload)
			}
		})
	}
}

func TestErrorsPreserveStatusAndRejectBrokenResponses(t *testing.T) {
	for _, tc := range []struct {
		name, method, body string
		status, want       int
	}{
		{"quota", "executor.execute", "dummy-credential must not leak", 429, 429},
		{"permission", "executor.execute_stream", "denied", 403, 403},
		{"unauthorized_without_stale_marker", "executor.execute", "denied", 401, 401},
		{"malformed", "executor.execute", `{"type":`, 200, 502},
		{"truncated", "executor.execute", `{"type":"message_start","message":{"id":"broken"}}`, 200, 502},
		{"embedded_error", "executor.execute", `{"type":"error","error":{"message":"failed"}}`, 200, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exchanges := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/client/llm_tokens" {
					exchanges++
					io.WriteString(w, `{"token":"dummy-token"}`)
					return
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			app := testApp(t, server.URL)
			if tc.method == "executor.execute_stream" {
				app.SetHostCaller(func(method string, payload any) (json.RawMessage, error) {
					switch method {
					case "host.http.do":
						return json.RawMessage(`{"StatusCode":200,"Body":"eyJ0b2tlbiI6ImR1bW15In0="}`), nil
					case "host.http.do_stream":
						return json.RawMessage(`{"status_code":403,"stream_id":"failed-stream"}`), nil
					case "host.http.stream_close":
						return json.RawMessage(`{}`), nil
					}
					return nil, fmt.Errorf("unexpected callback %s", method)
				})
			}
			req := completionRequest("zed/claude-sonnet-4-5")
			req["stream_id"] = "downstream-1"
			raw, _ := json.Marshal(req)
			response, err := app.HandleMethod(tc.method, raw)
			if err != nil {
				t.Fatal(err)
			}
			var envelope plugin.Envelope
			json.Unmarshal(response, &envelope)
			if envelope.OK || envelope.Error == nil || envelope.Error.HTTPStatus != tc.want || strings.Contains(string(response), "dummy-credential") {
				t.Fatalf("wrong error: %s", response)
			}
			if tc.status == 401 && exchanges != 1 {
				t.Fatal("retried unauthorized response without stale marker")
			}
		})
	}
	app := plugin.NewApp()
	defer app.Shutdown()
	for _, credential := range []string{`{"type":"zed","user_id":"42"}`, `{"type":"zed","user_id":42,"credential_json":"dummy"}`, `{"type":"zed","user_id":"42","credential_json":"bad\nheader"}`} {
		raw, _ := json.Marshal(pluginapi.AuthParseRequest{Provider: "zed", RawJSON: []byte(credential)})
		response, _ := app.HandleMethod("auth.parse", raw)
		var envelope plugin.Envelope
		json.Unmarshal(response, &envelope)
		if envelope.OK || envelope.Error.HTTPStatus != 400 {
			t.Fatalf("accepted malformed credential: %s", response)
		}
	}
}

func TestOrganizationScopedTokenExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/llm_tokens":
			if r.Header.Get("X-Zed-System-Id") != "" {
				t.Error("sent another installation's system ID")
			}
			var body struct {
				OrganizationID string `json:"organization_id"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.OrganizationID == "" {
				w.WriteHeader(422)
				return
			}
			if body.OrganizationID != "org-personal" {
				t.Error("wrong organization")
			}
			io.WriteString(w, `{"token":"organization-token"}`)
		case "/client/users/me":
			io.WriteString(w, `{"default_organization_id":"org-personal","organizations":[{"id":"org-personal","is_personal":true}]}`)
		case "/models":
			if r.Header.Get("X-Zed-Client-Supports-X-Ai") != "true" {
				t.Error("xAI discovery support was not advertised")
			}
			io.WriteString(w, `{"models":[{"id":"claude-sonnet-4-5","provider":"anthropic","display_name":"Claude Sonnet","max_token_count":200000,"max_output_tokens":64000}]}`)
		}
	}))
	defer server.Close()
	app := testApp(t, server.URL)
	var models pluginapi.ModelResponse
	rpc(t, app, "model.for_auth", map[string]any{"StorageJSON": []byte(`{"type":"zed","user_id":"42","credential_json":"dummy"}`), "host_callback_id": "request-1"}, &models)
	if len(models.Models) != 1 || models.Models[0].ID != "zed/anthropic/claude-sonnet-4-5" || models.Models[0].ContextLength != 200000 || models.Models[0].MaxCompletionTokens != 64000 {
		t.Fatalf("lost native model metadata: %+v", models)
	}
}

func TestFailedRefreshDoesNotReuseRejectedToken(t *testing.T) {
	exchanges, modelCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/client/llm_tokens" {
			exchanges++
			if exchanges == 1 {
				io.WriteString(w, `{"token":"rejected-token"}`)
			} else {
				w.WriteHeader(401)
			}
			return
		}
		modelCalls++
		w.Header().Set("X-Zed-Outdated-Token", "true")
		w.WriteHeader(401)
	}))
	defer server.Close()
	app := testApp(t, server.URL)
	raw, _ := json.Marshal(map[string]any{"StorageJSON": []byte(`{"type":"zed","user_id":"42","credential_json":"dummy"}`), "host_callback_id": "request-1"})
	for i := 0; i < 2; i++ {
		response, err := app.HandleMethod("model.for_auth", raw)
		if err != nil {
			t.Fatal(err)
		}
		var envelope plugin.Envelope
		json.Unmarshal(response, &envelope)
		if envelope.OK || envelope.Error.HTTPStatus != 401 {
			t.Fatalf("wrong refresh failure: %s", response)
		}
	}
	if exchanges != 3 || modelCalls != 1 {
		t.Fatalf("reused a rejected token after failed refresh: exchanges=%d models=%d", exchanges, modelCalls)
	}
}

func TestCredentialImport(t *testing.T) {
	app := plugin.NewApp()
	defer app.Shutdown()
	var parsed pluginapi.AuthParseResponse
	rpc(t, app, "auth.parse", pluginapi.AuthParseRequest{Provider: "zed", FileName: "zed-test.json", RawJSON: []byte(`{"type":"zed","user_id":"42","credential_json":"dummy-credential","prefix":"work","disabled":true}`)}, &parsed)
	if !parsed.Handled || parsed.Auth.Provider != "zed" || parsed.Auth.Label != "42" || parsed.Auth.FileName != "zed-test.json" || parsed.Auth.Prefix != "work" || !parsed.Auth.Disabled {
		t.Fatalf("incorrect imported account: %+v", parsed)
	}
	rpc(t, app, "auth.parse", pluginapi.AuthParseRequest{Provider: "codex", RawJSON: []byte(`{"type":"codex"}`)}, &parsed)
	if parsed.Handled {
		t.Fatal("claimed another provider's account")
	}
}

func TestRegistrationProvidesRequiredCPAMetadata(t *testing.T) {
	app := plugin.NewApp()
	defer app.Shutdown()
	var result struct {
		Metadata     pluginapi.Metadata
		Capabilities json.RawMessage
	}
	rpc(t, app, "plugin.register", map[string]any{}, &result)
	if result.Metadata.Name != "Zed" || result.Metadata.Logo != "https://zed.dev/favicon_black_64.png" || result.Metadata.Version == "" || result.Metadata.Author == "" || result.Metadata.GitHubRepository == "" {
		t.Fatal("CPA rejects plugins with missing required metadata")
	}
}
