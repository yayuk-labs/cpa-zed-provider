package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (a *App) settings() config { a.mu.Lock(); defer a.mu.Unlock(); return a.config }

type zedUserInfo struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	Plan         string `json:"plan"`
	PlanV2       string `json:"plan_v2"`
	PlanV3       string `json:"plan_v3"`
	ModelUsed    *int64 `json:"model_requests_used"`
	ModelLimit   any    `json:"model_requests_limit"`
	EditUsed     *int64 `json:"edit_predictions_used"`
	EditLimit    any    `json:"edit_predictions_limit"`
}

func (a *App) userInfo(c credential, callbackID string) (zedUserInfo, error) {
	cfg := a.settings()
	headers := http.Header{"Authorization": {c.userID + " " + c.secret}, "Accept": {"application/json"}, "Content-Type": {"application/json"}}
	systemID := c.systemID
	if systemID == "" {
		systemID = cfg.SystemID
	}
	if systemID != "" {
		headers.Set("X-Zed-System-Id", systemID)
	}
	var resp pluginapi.HTTPResponse
	if err := a.host("host.http.do", map[string]any{"method": "GET", "url": strings.TrimRight(cfg.BaseURL, "/") + "/client/users/me", "headers": headers, "host_callback_id": callbackID}, &resp); err != nil {
		return zedUserInfo{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zedUserInfo{}, upstreamError(resp.StatusCode, "user profile")
	}
	var response struct {
		zedUserInfo
		Plan json.RawMessage `json:"plan"`
		User *struct {
			Email       string `json:"email"`
			Name        string `json:"name"`
			GitHubLogin string `json:"github_login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body, &response); err != nil {
		return zedUserInfo{}, fail(502, "Invalid Zed user response")
	}
	user := response.zedUserInfo
	if len(response.Plan) > 0 && string(response.Plan) != "null" {
		if response.Plan[0] == '"' {
			if json.Unmarshal(response.Plan, &user.Plan) != nil {
				return zedUserInfo{}, fail(502, "Invalid Zed user response")
			}
		} else {
			var plan struct {
				PlanV3 string `json:"plan_v3"`
				Usage  struct {
					EditPredictions struct {
						Used  *int64 `json:"used"`
						Limit any    `json:"limit"`
					} `json:"edit_predictions"`
				} `json:"usage"`
			}
			if json.Unmarshal(response.Plan, &plan) != nil {
				return zedUserInfo{}, fail(502, "Invalid Zed user response")
			}
			user.PlanV3 = plan.PlanV3
			user.EditUsed, user.EditLimit = plan.Usage.EditPredictions.Used, plan.Usage.EditPredictions.Limit
		}
	}
	if response.User != nil {
		user.Email, user.Name = response.User.Email, response.User.Name
		if strings.TrimSpace(user.Name) == "" {
			user.Name = response.User.GitHubLogin
		}
	}
	return user, nil
}

func credentialKey(c credential) string {
	hash := sha256.Sum256([]byte(c.userID + "\x00" + c.secret + "\x00" + c.organization + "\x00" + c.systemID))
	return hex.EncodeToString(hash[:])
}

func catalogKey(req request) string {
	metadata := req.Metadata
	if len(metadata) == 0 {
		metadata = req.AuthMetadata
	}
	c, _ := credentialFrom(req.StorageJSON, metadata)
	return credentialKey(c)
}

func (a *App) llmToken(c credential, callbackID string, force bool) (string, error) {
	key := credentialKey(c)
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

func completionError(status int, operation string, body []byte, secrets ...string) error {
	base := upstreamError(status, operation)
	var data struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if len(body) > 64*1024 || json.Unmarshal(body, &data) != nil {
		return base
	}
	message := data.Message
	if message == "" {
		message = data.Error.Message
	}
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 2048 {
		message = message[:2048]
	}
	if message == "" {
		return base
	}
	return fail(base.(*RPCError).HTTPStatus, base.Error()+": "+message)
}

func stale(status int, headers http.Header) bool {
	if status == 401 {
		return true
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
		err = a.host("host.http.do", map[string]any{"method": method, "url": strings.TrimRight(cfg.BaseURL, "/") + path, "headers": zedHeaders(value, cfg.ZedVersion), "body": body, "host_callback_id": req.CallbackID}, &resp)
		if err != nil {
			return resp, err
		}
		if attempt == 0 && stale(resp.StatusCode, resp.Headers) {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if path == "/completions" {
				return resp, completionError(resp.StatusCode, path, resp.Body, c.secret, value)
			}
			return resp, upstreamError(resp.StatusCode, path)
		}
		return resp, nil
	}
	return pluginapi.HTTPResponse{}, fail(401, "Zed rejected the refreshed LLM token")
}

type zedModel struct {
	ID              string `json:"id"`
	Provider        string `json:"provider"`
	DisplayName     string `json:"display_name"`
	Context         int64  `json:"max_token_count"`
	Output          int64  `json:"max_output_tokens"`
	Disabled        bool   `json:"is_disabled"`
	Tools           bool   `json:"supports_tools"`
	Images          bool   `json:"supports_images"`
	Thinking        *bool  `json:"supports_thinking"`
	DisableThinking *bool  `json:"supports_disabling_thinking"`
	Efforts         []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"supported_effort_levels"`
}

func zedHeaders(token, version string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}, "Content-Type": {"application/json"}, "X-Zed-Version": {version}, "X-Zed-Client-Supports-X-Ai": {"true"}, "X-Zed-Client-Supports-Status-Messages": {"true"}, "X-Zed-Client-Supports-Stream-Ended-Request-Completion-Status": {"true"}}
}

func (m zedModel) thinkingSupport() *pluginapi.ThinkingSupport {
	if m.Thinking == nil || !*m.Thinking {
		return nil
	}
	support := &pluginapi.ThinkingSupport{Min: 1024, Max: int(m.Output) - 1, DynamicAllowed: true, ZeroAllowed: m.DisableThinking != nil && *m.DisableThinking}
	if support.Max < 0 {
		support.Max = 0
	}
	for _, effort := range m.Efforts {
		if _, err := strconv.Atoi(effort.Value); err != nil {
			support.Levels = append(support.Levels, effort.Value)
		}
	}
	if len(support.Levels) > 0 {
		support.Min, support.Max = 0, 0
	}
	return support
}

func (a *App) models(req request) (pluginapi.ModelResponse, error) {
	resp, err := a.cloud(req, "GET", "/models", nil)
	if err != nil {
		return pluginapi.ModelResponse{}, err
	}
	var data struct {
		Models []zedModel `json:"models"`
	}
	if err = json.Unmarshal(resp.Body, &data); err != nil || data.Models == nil {
		return pluginapi.ModelResponse{}, fail(502, "Invalid Zed model list")
	}
	result := pluginapi.ModelResponse{Provider: "zed", Models: []pluginapi.ModelInfo{}}
	catalog := make(map[string]zedModel)
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
		catalog[m.ID], catalog[id] = m, m
		info := pluginapi.ModelInfo{ID: "zed/" + id, Object: "model", OwnedBy: "zed", Name: id, DisplayName: display, Type: "zed", ContextLength: m.Context, MaxCompletionTokens: m.Output, InputTokenLimit: m.Context, OutputTokenLimit: m.Output, SupportedGenerationMethods: []string{"chat"}, SupportedInputModalities: []string{"text"}, SupportedOutputModalities: []string{"text"}, Thinking: m.thinkingSupport(), UserDefined: true}
		if m.Images {
			info.SupportedInputModalities = append(info.SupportedInputModalities, "image")
		}
		if m.Tools {
			info.SupportedParameters = append(info.SupportedParameters, "tools", "tool_choice")
		}
		if info.Thinking != nil {
			info.SupportedParameters = append(info.SupportedParameters, "reasoning_effort")
		}
		result.Models = append(result.Models, info)
	}
	a.mu.Lock()
	a.catalogs[catalogKey(req)] = catalog
	a.mu.Unlock()
	return result, nil
}
