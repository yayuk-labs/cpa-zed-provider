package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const ABIVersion = 1
const Version = "0.1.0"

type HostCaller func(string, any) (json.RawMessage, error)

type Envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

func ErrorEnvelope(code, message string, status int) []byte {
	raw, _ := json.Marshal(Envelope{Error: &RPCError{code, message, status}})
	return raw
}

func fail(status int, message string) error { return &RPCError{"zed_error", message, status} }

type config struct {
	BaseURL    string `yaml:"base_url"`
	ZedVersion string `yaml:"zed_version"`
	SystemID   string `yaml:"system_id"`
	LoginPort  int    `yaml:"login_port"`
}

type App struct {
	mu       sync.Mutex
	config   config
	call     HostCaller
	tokens   map[string]*token
	workers  sync.WaitGroup
	streams  map[string]string
	sessions map[string]*loginSession
	closed   bool
}

type token struct {
	mu           sync.Mutex
	value        string
	expires      time.Time
	organization string
}

func NewApp() *App {
	return &App{config: config{BaseURL: "https://cloud.zed.dev", ZedVersion: "0.222.4"}, tokens: make(map[string]*token), streams: make(map[string]string), sessions: make(map[string]*loginSession)}
}

func (a *App) SetHostCaller(call HostCaller) { a.mu.Lock(); defer a.mu.Unlock(); a.call = call }

func (a *App) host(method string, req any, out any) error {
	a.mu.Lock()
	call := a.call
	a.mu.Unlock()
	if call == nil {
		return fail(503, "CPA host callbacks are unavailable")
	}
	raw, err := call(method, req)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type request struct {
	Provider, AuthID, FileName, Model, SourceFormat, State string
	RawJSON, StorageJSON, Payload                          []byte
	ConfigYAML                                             []byte `json:"config_yaml"`
	Metadata, AuthMetadata                                 map[string]any
	Stream                                                 bool
	StreamID                                               string `json:"stream_id"`
	CallbackID                                             string `json:"host_callback_id"`
}

func (a *App) HandleMethod(method string, raw []byte) ([]byte, error) {
	var req request
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return ErrorEnvelope("invalid_request", "Invalid plugin request JSON", 400), nil
		}
	}
	result, err := a.handle(method, req)
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) {
			return ErrorEnvelope(rpcErr.Code, rpcErr.Message, rpcErr.HTTPStatus), nil
		}
		return ErrorEnvelope("plugin_error", err.Error(), 500), nil
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{OK: true, Result: payload})
}

func (a *App) handle(method string, req request) (any, error) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		if len(req.ConfigYAML) > 0 {
			a.mu.Lock()
			cfg := a.config
			a.mu.Unlock()
			if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
				return nil, fail(400, "Invalid Zed plugin configuration")
			}
			if !strings.HasPrefix(cfg.BaseURL, "https://") && !strings.HasPrefix(cfg.BaseURL, "http://127.0.0.1:") {
				return nil, fail(400, "base_url must use HTTPS (HTTP allowed for loopback tests)")
			}
			if cfg.LoginPort < 0 || cfg.LoginPort > 65535 || strings.ContainsAny(cfg.ZedVersion+cfg.SystemID, "\r\n") {
				return nil, fail(400, "Invalid Zed version, system ID, or login port")
			}
			a.mu.Lock()
			a.config = cfg
			a.tokens = make(map[string]*token)
			a.mu.Unlock()
		}
		a.mu.Lock()
		a.closed = false
		a.mu.Unlock()
		return map[string]any{"schema_version": 1, "metadata": pluginapi.Metadata{Name: "cpa-zed-provider", Version: Version, Author: "naufal", GitHubRepository: "https://github.com/yayuk-labs/cpa-zed-provider", ConfigFields: []pluginapi.ConfigField{{Name: "zed_version", Type: "string", Description: "Zed client version sent to Cloud"}, {Name: "system_id", Type: "string", Description: "Zed installation system ID"}, {Name: "login_port", Type: "integer", Description: "Loopback browser callback port; 0 chooses an available port"}}}, "capabilities": map[string]any{"auth_provider": true, "model_provider": true, "executor": true, "executor_model_scope": "oauth", "executor_input_formats": []string{"chat-completions"}, "executor_output_formats": []string{"chat-completions"}}}, nil
	case "auth.identifier", "executor.identifier":
		return map[string]string{"identifier": "zed"}, nil
	case "auth.login.start":
		return a.startLogin(req)
	case "auth.login.poll":
		return a.pollLogin(req)
	case "auth.refresh":
		return a.refresh(req)
	case "auth.parse":
		var data map[string]any
		if err := json.Unmarshal(req.RawJSON, &data); err != nil {
			return nil, fail(400, "Invalid auth file JSON")
		}
		if req.Provider != "zed" && text(data, "type") != "zed" && text(data, "provider") != "zed" {
			return pluginapi.AuthParseResponse{}, nil
		}
		if _, err := credentialFrom(req.RawJSON, nil); err != nil {
			return nil, err
		}
		return pluginapi.AuthParseResponse{Handled: true, Auth: authData(req.FileName, req.RawJSON, data)}, nil
	case "model.static":
		return pluginapi.ModelResponse{Provider: "zed", Models: []pluginapi.ModelInfo{}}, nil
	case "model.for_auth":
		return a.models(req)
	case "executor.execute":
		return a.execute(req)
	case "executor.execute_stream":
		return a.executeStream(req)
	case "executor.count_tokens":
		return nil, fail(501, "Zed Cloud does not expose token counting")
	case "executor.http_request":
		return nil, fail(501, "Arbitrary HTTP forwarding is not supported by the Zed provider")
	case "plugin.quiesce", "plugin.shutdown":
		a.Shutdown()
		return struct{}{}, nil
	default:
		return nil, fail(400, fmt.Sprintf("Unknown plugin method: %s", method))
	}
}

func text(data map[string]any, key string) string { s, _ := data[key].(string); return s }

func authData(filename string, raw []byte, data map[string]any) pluginapi.AuthData {
	id := text(data, "user_id")
	if filename == "" {
		filename = "zed-login-" + strings.Map(func(r rune) rune {
			if strings.ContainsRune("/\\:*?<>|\x00", r) || r < 32 {
				return '-'
			}
			return r
		}, id) + ".json"
	}
	disabled, _ := data["disabled"].(bool)
	return pluginapi.AuthData{Provider: "zed", ID: filename, FileName: filename, Label: id, Prefix: text(data, "prefix"), ProxyURL: text(data, "proxy_url"), Disabled: disabled, StorageJSON: raw, Metadata: data}
}

type credential struct{ userID, secret, organization, systemID string }

func credentialFrom(raw []byte, metadata map[string]any) (credential, error) {
	data := metadata
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			return credential{}, fail(400, "Invalid Zed credential JSON")
		}
	}
	c := credential{text(data, "user_id"), text(data, "credential_json"), text(data, "organization_id"), text(data, "system_id")}
	if strings.TrimSpace(c.userID) == "" || strings.TrimSpace(c.secret) == "" || strings.ContainsAny(c.userID+c.secret+c.systemID, "\r\n\x00") {
		return credential{}, fail(400, "Zed user_id and credential_json must be nonempty strings without control characters")
	}
	return c, nil
}

func (a *App) Shutdown() {
	a.mu.Lock()
	a.closed = true
	for _, session := range a.sessions {
		session.close()
	}
	a.sessions = make(map[string]*loginSession)
	streams := make(map[string]string, len(a.streams))
	for upstream, downstream := range a.streams {
		streams[upstream] = downstream
	}
	a.mu.Unlock()
	for upstream, downstream := range streams {
		a.host("host.http.stream_close", map[string]string{"stream_id": upstream}, nil)
		a.host("host.stream.close", map[string]string{"stream_id": downstream}, nil)
	}
	a.workers.Wait()
}
