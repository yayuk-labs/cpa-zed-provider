package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (a *App) settings() config { a.mu.Lock(); defer a.mu.Unlock(); return a.config }

func (a *App) llmToken(c credential, callbackID string, force bool) (string, error) {
	hash := sha256.Sum256([]byte(c.userID + "\x00" + c.secret + "\x00" + c.organization + "\x00" + c.systemID))
	key := hex.EncodeToString(hash[:])
	a.mu.Lock()
	entry := a.tokens[key]
	if entry == nil {
		entry = &token{}
		a.tokens[key] = entry
	}
	a.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if !force && entry.value != "" && time.Until(entry.expires) > time.Minute {
		return entry.value, nil
	}
	entry.value = ""
	entry.expires = time.Time{}
	cfg := a.settings()
	headers := http.Header{"Authorization": {c.userID + " " + c.secret}, "Content-Type": {"application/json"}}
	systemID := c.systemID
	if systemID == "" {
		systemID = cfg.SystemID
	}
	if systemID != "" {
		headers.Set("X-Zed-System-Id", systemID)
	}
	organization := c.organization
	if organization == "" {
		organization = entry.organization
	}
	var body []byte
	if organization != "" {
		body, _ = json.Marshal(map[string]string{"organization_id": organization})
	}
	var resp pluginapi.HTTPResponse
	exchange := func() error {
		return a.host("host.http.do", map[string]any{"method": "POST", "url": strings.TrimRight(cfg.BaseURL, "/") + "/client/llm_tokens", "headers": headers, "body": body, "host_callback_id": callbackID}, &resp)
	}
	err := exchange()
	if err != nil {
		return "", err
	}
	if organization == "" && (resp.StatusCode == 400 || resp.StatusCode == 422) {
		var user pluginapi.HTTPResponse
		if err = a.host("host.http.do", map[string]any{"method": "GET", "url": strings.TrimRight(cfg.BaseURL, "/") + "/client/users/me", "headers": headers, "host_callback_id": callbackID}, &user); err != nil {
			return "", err
		}
		if user.StatusCode < 200 || user.StatusCode >= 300 {
			return "", upstreamError(user.StatusCode, "organization discovery")
		}
		var info struct {
			Default       string `json:"default_organization_id"`
			Organizations []struct {
				ID       string `json:"id"`
				Personal bool   `json:"is_personal"`
			} `json:"organizations"`
		}
		if json.Unmarshal(user.Body, &info) != nil {
			return "", fail(502, "Invalid Zed organization response")
		}
		organization = info.Default
		if organization == "" {
			for _, org := range info.Organizations {
				if org.Personal {
					organization = org.ID
					break
				}
			}
		}
		if organization == "" {
			return "", fail(400, "Zed requires an organization_id in the auth file")
		}
		body, _ = json.Marshal(map[string]string{"organization_id": organization})
		if err = exchange(); err != nil {
			return "", err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", upstreamError(resp.StatusCode, "credential exchange")
	}
	var data struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(resp.Body, &data); err != nil || data.Token == "" || strings.ContainsAny(data.Token, "\r\n\x00") {
		return "", fail(502, "Zed returned an invalid LLM token")
	}
	entry.value = data.Token
	entry.organization = organization
	entry.expires = time.Now().Add(time.Hour)
	return entry.value, nil
}

func upstreamError(status int, operation string) error {
	if status < 400 || status > 599 {
		status = 502
	}
	return fail(status, fmt.Sprintf("Zed %s failed (HTTP %d)", operation, status))
}

func stale(status int, headers http.Header) bool {
	if status != 401 {
		return false
	}
	for key := range headers {
		if strings.EqualFold(key, "x-zed-expired-token") || strings.EqualFold(key, "x-zed-outdated-token") {
			return true
		}
	}
	return false
}

func (a *App) cloud(req request, method, path string, body []byte) (pluginapi.HTTPResponse, error) {
	c, err := credentialFrom(req.StorageJSON, req.Metadata)
	if err != nil {
		return pluginapi.HTTPResponse{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		value, err := a.llmToken(c, req.CallbackID, attempt == 1)
		if err != nil {
			return pluginapi.HTTPResponse{}, err
		}
		cfg := a.settings()
		var resp pluginapi.HTTPResponse
		err = a.host("host.http.do", map[string]any{"method": method, "url": strings.TrimRight(cfg.BaseURL, "/") + path, "headers": http.Header{"Authorization": {"Bearer " + value}, "Content-Type": {"application/json"}, "X-Zed-Version": {cfg.ZedVersion}, "X-Zed-Client-Supports-X-Ai": {"true"}}, "body": body, "host_callback_id": req.CallbackID}, &resp)
		if err != nil {
			return resp, err
		}
		if attempt == 0 && stale(resp.StatusCode, resp.Headers) {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp, upstreamError(resp.StatusCode, path)
		}
		return resp, nil
	}
	return pluginapi.HTTPResponse{}, fail(401, "Zed rejected the refreshed LLM token")
}

func (a *App) models(req request) (pluginapi.ModelResponse, error) {
	resp, err := a.cloud(req, "GET", "/models", nil)
	if err != nil {
		return pluginapi.ModelResponse{}, err
	}
	var data struct {
		Models []struct {
			ID          string `json:"id"`
			Provider    string `json:"provider"`
			DisplayName string `json:"display_name"`
			Context     int64  `json:"max_token_count"`
			Output      int64  `json:"max_output_tokens"`
			Disabled    bool   `json:"is_disabled"`
		} `json:"models"`
	}
	if err = json.Unmarshal(resp.Body, &data); err != nil || data.Models == nil {
		return pluginapi.ModelResponse{}, fail(502, "Invalid Zed model list")
	}
	result := pluginapi.ModelResponse{Provider: "zed", Models: []pluginapi.ModelInfo{}}
	for _, m := range data.Models {
		if m.ID == "" || m.Disabled {
			continue
		}
		id := m.ID
		if m.Provider != "" && !strings.Contains(id, "/") {
			id = m.Provider + "/" + id
		}
		display := m.DisplayName
		if display == "" {
			display = m.ID
		}
		result.Models = append(result.Models, pluginapi.ModelInfo{ID: "zed/" + id, Object: "model", OwnedBy: "zed", Name: id, DisplayName: display, Type: "zed", ContextLength: m.Context, MaxCompletionTokens: m.Output, InputTokenLimit: m.Context, OutputTokenLimit: m.Output, SupportedGenerationMethods: []string{"chat"}, UserDefined: true})
	}
	return result, nil
}
