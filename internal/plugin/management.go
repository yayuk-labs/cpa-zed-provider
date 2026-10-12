package plugin

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

//go:embed assets/login.html
var loginPage []byte

func (a *App) management(req request) (pluginapi.ManagementResponse, error) {
	if req.Method == http.MethodGet && req.Path == "/v0/resource/plugins/cpa-zed-provider/login" {
		return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Cache-Control":           {"no-store"},
			"Referrer-Policy":         {"no-referrer"},
			"X-Content-Type-Options":  {"nosniff"},
			"Content-Security-Policy": {"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src https://zed.dev; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"},
		}, Body: loginPage}, nil
	}
	if req.Method == http.MethodPost && req.Path == "/v0/management/plugins/zed/callback" {
		err := a.submitLoginCallback(req.Body)
		status := http.StatusOK
		body := map[string]string{"status": "ok"}
		if err != nil {
			rpcErr := err.(*RPCError)
			status = rpcErr.HTTPStatus
			body = map[string]string{"status": "error", "error": rpcErr.Message}
		}
		raw, _ := json.Marshal(body)
		return pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: raw}, nil
	}
	return pluginapi.ManagementResponse{StatusCode: http.StatusNotFound}, nil
}
