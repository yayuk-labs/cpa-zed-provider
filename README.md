# CPA Zed Provider

Zed Cloud AI provider for CLIProxyAPI, packaged as a standard C-ABI shared-library plugin using CPA's public translator SDK.

Includes browser login, credential-file import, account-preserving sign-in, cached LLM tokens, token refresh, organization-scoped token compatibility, dynamic models, completions, and incremental streaming. Anthropic, OpenAI Responses, Google Gemini, and xAI requests use their native formats. CPA handles downstream Chat Completions, Claude Messages, and Responses compatibility and publishes usage to other plugins.

## Build

Requires Go 1.26+, CGO, and a native C compiler. The CPA SDK is resolved from its Go module. Uses CPA's public plugin SDK and existing plugin management/resource routes. CPA source changes are not required.

From `cpa-zed-provider`, build for your native platform:

```sh
# macOS
CGO_ENABLED=1 go build -tags cshared -buildmode=c-shared -o dist/cpa-zed-provider.dylib ./cmd/cpa-zed-provider

# Linux
CGO_ENABLED=1 go build -tags cshared -buildmode=c-shared -o dist/cpa-zed-provider.so ./cmd/cpa-zed-provider
```

On Windows, install a matching MinGW compiler and build with CGO enabled:

```powershell
$env:CGO_ENABLED = "1"
go build -tags cshared -buildmode=c-shared -o dist/cpa-zed-provider.dll ./cmd/cpa-zed-provider
```

## Install

To install from CPA's Plugin Store, add this registry under `plugins.store-sources`, then choose **Zed** in the store:

```yaml
plugins:
  store-sources:
    - "https://raw.githubusercontent.com/yayuk-labs/cpa-zed-provider/main/registry.json"
```

Tagged releases publish Linux amd64 and arm64 packages. For manual installation, copy the compiled library into CPA's `plugins/` directory. The generated `.h` file is for C callers and is not needed by CPA. Use a CPA build with plugin support and enable the plugin:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    cpa-zed-provider:
      enabled: true
      zed_version: "0.222.4"
      login_port: 0
      # system_id: "your-own-zed-installation-id"
```

Restart CPA. `zed_version` defaults to `0.222.4`; set it to your installed Zed version if Cloud requires a newer client. `login_port: 0` selects an available loopback port. Set a fixed port when using SSH forwarding. `system_id` is optional and omitted by default; use your own installation ID if needed. An auth file's `system_id` overrides the plugin setting.

## Sign in

Use CPA's management key to start login:

```sh
curl 'http://127.0.0.1:8317/v8/management/oauth/auth-url?provider=zed' \
  -H 'Authorization: Bearer MANAGEMENT_KEY'
```

Open the returned `url` in a browser on the CPA machine. Zed redirects to the plugin's loopback listener with an encrypted credential. RSA private keys stay in memory; sessions expire after ten minutes.

### Remote CPA (v0.1.2+)

Open **Zed** in CPA's plugin menu, or visit `/v0/resource/plugins/cpa-zed-provider/login` on your CPA server. Enter the CPA management key and click **Start Zed sign-in**, then **Open Zed sign-in**. After signing in, copy the complete redirected localhost URL, paste it into this page's **Callback URL** field, and click **Save Zed account**. The localhost page may fail to load when CPA is remote; copy its URL anyway. The page keeps the management key in memory only and clears it after saving.

This flow uses the plugin's authenticated callback endpoint and requires no CPA patch or SSH forwarding. CPA's generic OAuth callback field cannot accept Zed's native `user_id`/`access_token` callback.

For API clients, submit the URL with the `state` returned when starting login:

```sh
curl -X POST 'http://127.0.0.1:8317/v0/management/plugins/zed/callback' \
  -H 'Authorization: Bearer MANAGEMENT_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"state":"RETURNED_STATE","redirect_url":"FULL_ZED_CALLBACK_URL"}'
```

Poll the returned `state` until CPA reports `ok`. This final poll persists the credential through CPA's auth store:

```sh
curl 'http://127.0.0.1:8317/v8/management/oauth/status?state=RETURNED_STATE' \
  -H 'Authorization: Bearer MANAGEMENT_KEY'
```

Signing in again preserves the matching account's filename, routing prefix, disabled state, organization, and other stored settings.

## Import credentials

Existing Zed auth files are accepted directly:

```json
{
  "type": "zed",
  "user_id": "YOUR_USER_ID",
  "credential_json": "YOUR_NATIVE_ZED_CREDENTIAL"
}
```

`credential_json` is an opaque string, not an LLM bearer token. Optional `organization_id` selects a Zed organization; otherwise the plugin discovers the default/personal organization when the token endpoint requires it. Existing `prefix`, `disabled`, `proxy_url`, `system_id`, and other metadata remain in the auth file.

Place the file in CPA's configured auth directory, or upload through management:

```sh
curl -X POST 'http://127.0.0.1:8317/v8/management/credentials?name=zed-account.json' \
  -H 'Authorization: Bearer MANAGEMENT_KEY' \
  -H 'Content-Type: application/json' \
  --data-binary @zed-account.json
```

## Request a model

Read `/v1/models` for exact IDs. Zed models use the `zed/` namespace, usually including the upstream provider: `zed/anthropic/claude-sonnet-4-5`, `zed/open_ai/gpt-4.1`, `zed/google/gemini-2.5-pro`, or `zed/x_ai/grok-3`. The available models come from the account's Cloud catalog. An auth routing prefix adds another prefix as usual in CPA.

```sh
curl 'http://127.0.0.1:8317/v1/chat/completions' \
  -H 'Authorization: Bearer CPA_CLIENT_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"zed/anthropic/claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

CPA host HTTP callbacks handle transport and request cancellation. These callbacks use CPA's global proxy configuration; a stored per-account `proxy_url` is preserved but is not applied by the host callback API. Streaming uses the host's HTTP and executor stream bridges, preserves fragmented NDJSON/UTF-8, and emits OpenAI SSE with a final `[DONE]`. Shutdown closes outstanding streams and login listeners. Token-counting and arbitrary authenticated HTTP forwarding return HTTP 501 because this plugin does not implement those operations.

## Verify

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

The integration smoke check requires Python 3, OpenSSL, the compiled plugin, and a CPA executable. It starts isolated servers with dummy credentials, verifies plugin loading, model registration, completions, streaming, downstream protocol translation, local encrypted login, plugin-only remote callbacks, authentication/replay rejection, and account preservation, then stops them:

```sh
python3 scripts/smoke.py --cpa /path/to/cli-proxy-api --plugin dist/cpa-zed-provider.dylib
```

Verification uses a local fake Zed server. Access with a real Zed account must be checked against that account's Cloud permissions and installed client version. Only macOS ARM64 has been built and tested in this workspace.

## Sources

- [CPA plugin examples](https://github.com/router-for-me/CLIProxyAPI/tree/main/examples/plugin).
- [Zed Cloud request and model types](https://github.com/zed-industries/zed/blob/main/crates/cloud_llm_client/src/cloud_llm_client.rs) and [organization/token types](https://github.com/zed-industries/zed/blob/main/crates/cloud_api_types/src/cloud_api_types.rs).
- The C-ABI bridge's MIT notice is retained in [LICENSE](LICENSE).
