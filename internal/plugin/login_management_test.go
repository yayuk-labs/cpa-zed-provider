package plugin_test

import (
	"net/http"
	"strings"
	"testing"

	"cpa-zed-provider/internal/plugin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestZedLoginPageIsRegisteredAndServed(t *testing.T) {
	app := plugin.NewApp()
	defer app.Shutdown()
	var routes pluginapi.ManagementRegistrationResponse
	rpc(t, app, "management.register", pluginapi.ManagementRegistrationRequest{}, &routes)
	if len(routes.Resources) != 1 || routes.Resources[0].Path != "/login" || routes.Resources[0].Menu != "Zed" {
		t.Fatalf("Zed login page not registered: %+v", routes.Resources)
	}
	if len(routes.Routes) != 1 || routes.Routes[0].Method != http.MethodPost || routes.Routes[0].Path != "/plugins/zed/callback" {
		t.Fatalf("authenticated callback not registered: %+v", routes.Routes)
	}
	var page pluginapi.ManagementResponse
	rpc(t, app, "management.handle", pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/cpa-zed-provider/login"}, &page)
	if page.StatusCode != http.StatusOK || !strings.Contains(string(page.Body), "<title>Zed</title>") || !strings.Contains(string(page.Body), "Callback URL") {
		t.Fatal("Zed login page missing")
	}
	if page.Headers.Get("Cache-Control") != "no-store" || page.Headers.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("login page must not cache or leak referrers")
	}
}
