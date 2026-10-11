package plugin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type loginSession struct {
	mu      sync.Mutex
	key     *rsa.PrivateKey
	server  *http.Server
	timer   *time.Timer
	expires time.Time
	auth    *pluginapi.AuthData
}

func (s *loginSession) close() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.server.Close()
}

func (a *App) startLogin(req request) (pluginapi.AuthLoginStartResponse, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return pluginapi.AuthLoginStartResponse{}, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.settings().LoginPort)))
	if err != nil {
		return pluginapi.AuthLoginStartResponse{}, fail(503, "Could not bind Zed login callback port")
	}
	state := uuid()
	session := &loginSession{key: key, expires: time.Now().Add(10 * time.Minute)}
	session.server = &http.Server{Handler: http.HandlerFunc(session.callback), ReadHeaderTimeout: 10 * time.Second}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		listener.Close()
		return pluginapi.AuthLoginStartResponse{}, fail(503, "Zed plugin is shutting down")
	}
	a.sessions[state] = session
	session.timer = time.AfterFunc(time.Until(session.expires), func() {
		a.mu.Lock()
		if a.sessions[state] == session {
			delete(a.sessions, state)
		}
		session.close()
		a.mu.Unlock()
	})
	a.workers.Add(1)
	a.mu.Unlock()
	go func() { defer a.workers.Done(); session.server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	query := url.Values{"native_app_port": {strconv.Itoa(port)}, "native_app_public_key": {base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))}}
	return pluginapi.AuthLoginStartResponse{Provider: "zed", URL: "https://zed.dev/native_app_signin?" + query.Encode(), State: state, ExpiresAt: session.expires, Metadata: map[string]any{"loopback_callback_url": "http://127.0.0.1:" + strconv.Itoa(port) + "/"}}, nil
}

func (s *loginSession) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auth != nil {
		http.Error(w, "Callback already completed", 409)
		return
	}
	if time.Now().After(s.expires) {
		http.Error(w, "Login session expired", 410)
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	ciphertext := strings.TrimSpace(r.URL.Query().Get("access_token"))
	if userID == "" || len(userID) > 256 || len(ciphertext) > 1024 {
		http.Error(w, "Invalid user_id or access_token", 400)
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(ciphertext, "="))
	if err != nil {
		http.Error(w, "Invalid encrypted credential", 400)
		return
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.key, decoded, nil)
	if err != nil || !utf8.Valid(plaintext) {
		http.Error(w, "Invalid encrypted credential", 400)
		return
	}
	data := map[string]any{"type": "zed", "user_id": userID, "credential_json": string(plaintext)}
	raw, _ := json.Marshal(data)
	if _, err = credentialFrom(raw, nil); err != nil {
		http.Error(w, "Invalid Zed credential", 400)
		return
	}
	auth := authData("", raw, data)
	s.auth = &auth
	s.key = nil
	http.Redirect(w, r, "https://zed.dev/native_app_signin_succeeded", http.StatusTemporaryRedirect)
}

func (a *App) pollLogin(req request) (pluginapi.AuthLoginPollResponse, error) {
	a.mu.Lock()
	session := a.sessions[req.State]
	a.mu.Unlock()
	if session == nil {
		return pluginapi.AuthLoginPollResponse{Status: "error", Message: "Unknown or expired Zed login session"}, nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expires) {
		return pluginapi.AuthLoginPollResponse{Status: "error", Message: "Zed login session expired"}, nil
	}
	if session.auth == nil {
		return pluginapi.AuthLoginPollResponse{Status: "pending"}, nil
	}
	auth, err := a.preserveAccount(*session.auth)
	if err != nil {
		return pluginapi.AuthLoginPollResponse{}, err
	}
	a.mu.Lock()
	delete(a.sessions, req.State)
	session.close()
	a.mu.Unlock()
	return pluginapi.AuthLoginPollResponse{Status: "success", Auth: auth}, nil
}

func (a *App) preserveAccount(auth pluginapi.AuthData) (pluginapi.AuthData, error) {
	var listed struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := a.host("host.auth.list", struct{}{}, &listed); err != nil {
		return auth, err
	}
	userID := text(auth.Metadata, "user_id")
	for _, entry := range listed.Files {
		if entry.RuntimeOnly || entry.Provider != "zed" && entry.Type != "zed" {
			continue
		}
		var stored pluginapi.HostAuthGetResponse
		if err := a.host("host.auth.get", pluginapi.HostAuthGetRequest{AuthIndex: entry.AuthIndex}, &stored); err != nil {
			return auth, err
		}
		var data map[string]any
		if json.Unmarshal(stored.JSON, &data) != nil || data == nil {
			return auth, fail(500, "Cannot preserve invalid existing Zed auth data")
		}
		previous := text(data, "user_id")
		matches := previous == userID
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(previous, userID)
		}
		if !matches {
			continue
		}
		for _, key := range []string{"type", "user_id", "credential_json"} {
			data[key] = auth.Metadata[key]
		}
		data["last_refreshed_at"] = time.Now().UTC().Format(time.RFC3339)
		raw, err := json.Marshal(data)
		if err != nil {
			return auth, err
		}
		auth = authData(stored.Name, raw, data)
		auth.ID = entry.ID
		return auth, nil
	}
	return auth, nil
}

func (a *App) refresh(req request) (pluginapi.AuthRefreshResponse, error) {
	c, err := credentialFrom(req.StorageJSON, req.Metadata)
	if err != nil {
		return pluginapi.AuthRefreshResponse{}, err
	}
	if _, err = a.llmToken(c, req.CallbackID, true); err != nil {
		return pluginapi.AuthRefreshResponse{}, err
	}
	var data map[string]any
	if len(req.StorageJSON) > 0 {
		err = json.Unmarshal(req.StorageJSON, &data)
	} else {
		data = req.Metadata
	}
	if err != nil {
		return pluginapi.AuthRefreshResponse{}, fmt.Errorf("decode Zed auth storage: %w", err)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return pluginapi.AuthRefreshResponse{}, err
	}
	auth := authData(req.AuthID, raw, data)
	// CPA retains the selected credential's filename independently of its runtime ID.
	auth.FileName = ""
	next := time.Now().Add(59 * time.Minute)
	auth.NextRefreshAfter = next
	return pluginapi.AuthRefreshResponse{Auth: auth, NextRefreshAfter: next}, nil
}
