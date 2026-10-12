#!/usr/bin/env python3
"""Exercise the compiled plugin through an unmodified CPA server and fake Zed Cloud."""
import argparse
import base64
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


EVENTS = '\n'.join(json.dumps(event) for event in [
    {"type": "message_start", "message": {"id": "msg_smoke", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 4}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}},
    {"type": "message_stop"},
]).encode()


class Zed(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        assert self.path == "/models", self.path
        self.respond(200, json.dumps({"models": [{"id": "claude-sonnet-4-5", "provider": "anthropic"}]}).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/client/llm_tokens":
            assert self.headers["Authorization"] == "42 dummy-credential"
            self.respond(200, b'{"token":"dummy-llm-token"}')
        else:
            assert self.path == "/completions"
            envelope = json.loads(body)
            assert envelope["provider"] == "anthropic"
            assert envelope["model"] == "claude-sonnet-4-5"
            assert envelope["provider_request"]["messages"]
            self.respond(200, EVENTS)

    def respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpa", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    args = parser.parse_args()
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Zed)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cpa-zed-smoke-") as directory:
            root = Path(directory)
            (root / "plugins").mkdir()
            (root / "auths").mkdir()
            shutil.copy2(args.plugin, root / "plugins" / args.plugin.name)
            auth = root / "auths" / "zed-smoke.json"
            auth.write_text(json.dumps({"type": "zed", "user_id": "42", "credential_json": "dummy-credential", "note": "preserve this"}))
            auth.chmod(0o600)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            config = root / "config.yaml"
            config.write_text(f'''config-version: 8
server:
  host: "127.0.0.1"
  port: {port}
management:
  secret-key: "smoke-management"
  disable-control-panel: true
access:
  api-keys: ["smoke-client"]
oauth:
  auth-dir: {json.dumps(str(root / "auths"))}
plugins:
  enabled: true
  dir: {json.dumps(str(root / "plugins"))}
  configs:
    cpa-zed-provider:
      enabled: true
      base_url: "http://127.0.0.1:{upstream.server_port}"
''')
            with (root / "cpa.log").open("w+") as log:
                process = subprocess.Popen([str(args.cpa.resolve()), "-config", str(config), "-local-model"], cwd=root, stdout=log, stderr=log)
                try:
                    def call(path, body=None, key="smoke-client"):
                        request = urllib.request.Request(f"http://127.0.0.1:{port}" + path, data=None if body is None else json.dumps(body).encode(), headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
                        with urllib.request.urlopen(request, timeout=10) as response:
                            return response.read()

                    deadline = time.monotonic() + 20
                    while True:
                        try:
                            models = json.loads(call("/v1/models"))
                            if any(m["id"] == "zed/anthropic/claude-sonnet-4-5" for m in models["data"]):
                                break
                        except (OSError, urllib.error.URLError):
                            pass
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("CPA did not register Zed's auth-bound model")
                        time.sleep(0.1)
                    plugins = json.loads(call("/v8/management/plugins", key="smoke-management"))
                    assert "cpa-zed-provider" in json.dumps(plugins), plugins
                    zed = next(item for item in plugins["plugins"] if item["id"] == "cpa-zed-provider")
                    assert zed["metadata"]["name"] == "Zed", zed
                    assert zed["logo"] == "https://zed.dev/favicon_black_64.png", zed
                    assert any(menu["path"].endswith("/login") for menu in zed["menus"]), zed
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v0/resource/plugins/cpa-zed-provider/login") as page:
                        assert b"<title>Zed</title>" in page.read()
                        assert page.headers["Cache-Control"] == "no-store"
                    request = {"model": "zed/anthropic/claude-sonnet-4-5", "messages": [{"role": "user", "content": "Hello"}]}
                    response = json.loads(call("/v1/chat/completions", request))
                    assert response["choices"][0]["message"]["content"] == "Hello", response
                    assert response["usage"]["total_tokens"] == 6, response
                    stream = call("/v1/chat/completions", dict(request, stream=True))
                    assert b"Hello" in stream and b"data: [DONE]" in stream, stream
                    claude = json.loads(call("/v1/messages", dict(request, max_tokens=128)))
                    assert claude["content"][0]["text"] == "Hello", claude
                    responses = json.loads(call("/v1/responses", {"model": request["model"], "input": "Hello"}))
                    assert "Hello" in json.dumps(responses), responses
                    login = json.loads(call("/v8/management/oauth/auth-url?provider=zed", key="smoke-management"))
                    assert login["url"].startswith("https://zed.dev/native_app_signin?"), login
                    poll = json.loads(call("/v8/management/oauth/status?state=" + login["state"], key="smoke-management"))
                    assert poll["status"] == "wait", poll
                    query = urllib.parse.parse_qs(urllib.parse.urlparse(login["url"]).query)
                    public_key = root / "login-public.der"
                    public_key.write_bytes(base64.urlsafe_b64decode(query["native_app_public_key"][0] + "=="))
                    encrypted = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-keyform", "DER", "-inkey", str(public_key), "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"], input=b"dummy-credential", capture_output=True, check=True).stdout
                    callback_url = "http://127.0.0.1:" + query["native_app_port"][0] + "/?" + urllib.parse.urlencode({"user_id": "42", "access_token": base64.urlsafe_b64encode(encrypted).decode()})
                    callback = {"state": login["state"], "redirect_url": callback_url}
                    try:
                        call("/v8/management/oauth/callback", {"provider": "zed", "redirect_url": callback_url}, key="smoke-management")
                        raise AssertionError("smoke test must use CPA without loopback forwarding")
                    except urllib.error.HTTPError as error:
                        assert error.code == 400, error.code
                    try:
                        call("/v0/management/plugins/zed/callback", callback, key="")
                        raise AssertionError("callback accepted without management authentication")
                    except urllib.error.HTTPError as error:
                        assert error.code == 401, error.code
                    submitted = json.loads(call("/v0/management/plugins/zed/callback", callback, key="smoke-management"))
                    assert submitted["status"] == "ok", submitted
                    try:
                        call("/v0/management/plugins/zed/callback", callback, key="smoke-management")
                        raise AssertionError("callback replay was accepted")
                    except urllib.error.HTTPError as error:
                        assert error.code == 409, error.code
                    poll = json.loads(call("/v8/management/oauth/status?state=" + login["state"], key="smoke-management"))
                    assert poll["status"] == "ok", poll
                    assert json.loads(auth.read_text())["note"] == "preserve this"
                    assert list((root / "auths").glob("*.json")) == [auth], "relogin created a duplicate account"
                    print("PASS: CPA loads plugin; auth/models, Chat, streaming, Claude, Responses, plugin-only remote login, replay rejection and account preservation work")
                except Exception:
                    log.seek(0)
                    print(log.read())
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join()


if __name__ == "__main__":
    main()
