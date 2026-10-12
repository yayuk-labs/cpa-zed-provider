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
	mu          sync.Mutex
	key         *rsa.PrivateKey
	server      *http.Server
	timer       *time.Timer
	expires     time.Time
	auth        *pluginapi.AuthData
	callbackURL string
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
	port := listener.Addr().(*net.TCPAddr).Port
	session := &loginSession{key: key, expires: time.Now().Add(10 * time.Minute), callbackURL: "http://127.0.0.1:" + strconv.Itoa(port) + "/"}
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
	query := url.Values{"native_app_port": {strconv.Itoa(port)}, "native_app_public_key": {base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))}}
	return pluginapi.AuthLoginStartResponse{Provider: "zed", URL: "https://zed.dev/native_app_signin?" + query.Encode(), State: state, ExpiresAt: session.expires}, nil
}

func (s *loginSession) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if err := s.complete(r.URL.Query()); err != nil {
		rpcErr := err.(*RPCError)
		http.Error(w, rpcErr.Message, rpcErr.HTTPStatus)
		return
	}
	http.Redirect(w, r, "https://zed.dev/native_app_signin_succeeded", http.StatusTemporaryRedirect)
}

func (s *loginSession) complete(query url.Values) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auth != nil {
		return fail(409, "Callback already completed")
	}
	if time.Now().After(s.expires) {
		return fail(410, "Login session expired")
	}
	userID := strings.TrimSpace(query.Get("user_id"))
	ciphertext := strings.TrimSpace(query.Get("access_token"))
	if userID == "" || len(userID) > 256 || len(ciphertext) > 1024 {
		return fail(400, "Invalid user_id or access_token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(ciphertext, "="))
	if err != nil {
		return fail(400, "Invalid encrypted credential")
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.key, decoded, nil)
	if err != nil || !utf8.Valid(plaintext) {
		return fail(400, "Invalid encrypted credential")
	}
	data := map[string]any{"type": "zed", "user_id": userID, "credential_json": string(plaintext)}
	raw, _ := json.Marshal(data)
	if _, err = credentialFrom(raw, nil); err != nil {
		return fail(400, "Invalid Zed credential")
	}
	auth := authData("", raw, data)
	s.auth = &auth
	s.key = nil
	return nil
}

func (a *App) submitLoginCallback(body []byte) error {
	var submitted struct {
		State       string `json:"state"`
		RedirectURL string `json:"redirect_url"`
	}
	if len(body) > 4096 || json.Unmarshal(body, &submitted) != nil {
		return fail(400, "Invalid callback submission")
	}
	a.mu.Lock()
	session := a.sessions[submitted.State]
	a.mu.Unlock()
	if session == nil {
		return fail(410, "Unknown or expired Zed login session. Start sign-in again.")
	}
	u, err := url.Parse(strings.TrimSpace(submitted.RedirectURL))
	if err != nil || u.User != nil || u.Fragment != "" {
		return fail(400, "Invalid Zed callback URL")
	}
	query := u.Query()
	u.RawQuery = ""
	u.ForceQuery = false
	if u.String() != session.callbackURL {
		return fail(400, "Callback URL does not match this Zed login. Paste the URL from the current sign-in.")
	}
	return session.complete(query)
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
