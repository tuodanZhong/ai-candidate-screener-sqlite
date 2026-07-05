#!/usr/bin/env python3
"""
Local SQLite server for the AI candidate screener.

Run:
  python3 server.py

Then open:
  http://127.0.0.1:8765/

All persisted app data is stored in:
  data/candidates.sqlite3
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "candidates.sqlite3"
MAX_BODY_BYTES = 80 * 1024 * 1024
MAX_FETCH_BYTES = 2 * 1024 * 1024
SESSION_COOKIE = "screener_session"
SESSION_TTL_SECONDS = 12 * 60 * 60


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_session_secret() -> str:
    secret = os.environ.get("APP_SESSION_SECRET", "").strip()
    if not secret:
        secret = getattr(get_session_secret, "_fallback", "")
        if not secret:
            secret = secrets.token_urlsafe(32)
            setattr(get_session_secret, "_fallback", secret)
    return secret


def sign_session(payload: str) -> str:
    digest = hmac.new(get_session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def make_session_value() -> str:
    expires = int(time.time()) + SESSION_TTL_SECONDS
    nonce = secrets.token_urlsafe(18)
    payload = f"{expires}.{nonce}"
    return f"{payload}.{sign_session(payload)}"


def valid_session_value(value: str) -> bool:
    try:
        expires_s, nonce, signature = value.split(".", 2)
        payload = f"{expires_s}.{nonce}"
        if not hmac.compare_digest(signature, sign_session(payload)):
            return False
        return int(expires_s) >= int(time.time())
    except Exception:
        return False


def configured_password() -> str:
    return os.environ.get("APP_PASSWORD", "").strip()


def configured_users() -> dict[str, str]:
    raw = os.environ.get("APP_USERS", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items() if str(k).strip()}
        except Exception:
            return {}
    password = configured_password()
    return {"admin": password} if password else {}


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip_depth += 1
            return
        if tag in {"p", "div", "section", "article", "li", "br", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")
        if tag == "meta":
            attr = dict(attrs)
            content = attr.get("content")
            if content and attr.get("name") in {"description", "keywords"}:
                self.parts.append("\n" + content)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self.skip_depth:
            self.skip_depth -= 1
        elif tag in {"p", "div", "section", "article", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t\r\f\v]+", " ", "".join(self.parts))).strip()


def html_to_text(html: str) -> str:
    parser = TextExtractor()
    parser.feed(html)
    return parser.text()


def decode_bytes(raw: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type or "", re.I)
    encodings = [match.group(1)] if match else []
    encodings += ["utf-8", "gb18030", "latin-1"]
    for enc in encodings:
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "ignore")


def infer_related_urls(url: str) -> list[str]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if host.endswith("github.io"):
        user = host.split(".")[0]
        repo = parsed.path.strip("/").split("/", 1)[0]
        if user and repo:
            return [f"https://github.com/{user}/{repo}"]
    return []


def fetch_url_text(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return {"url": url, "ok": False, "error": "仅支持 http/https 链接"}
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 CandidateScreener/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain,application/json;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(MAX_FETCH_BYTES + 1)
            truncated = len(raw) > MAX_FETCH_BYTES
            raw = raw[:MAX_FETCH_BYTES]
            content_type = resp.headers.get("content-type", "")
            text = decode_bytes(raw, content_type)
            if "html" in content_type or text.lstrip().startswith("<"):
                text = html_to_text(text)
            text = text[:20000]
            return {
                "url": url,
                "ok": True,
                "status": getattr(resp, "status", None),
                "contentType": content_type,
                "truncated": truncated,
                "text": text,
            }
    except urllib.error.HTTPError as exc:
        return {"url": url, "ok": False, "status": exc.code, "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"url": url, "ok": False, "error": str(exc)}


def call_deepseek(payload: dict) -> tuple[int, bytes, str]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        body = json.dumps(
            {"error": "服务端未配置 DEEPSEEK_API_KEY"},
            ensure_ascii=False,
        ).encode("utf-8")
        return HTTPStatus.BAD_GATEWAY, body, "application/json; charset=utf-8"

    allowed = {
        "model",
        "messages",
        "response_format",
        "max_tokens",
        "temperature",
        "top_p",
        "stream",
    }
    forwarded = {k: v for k, v in payload.items() if k in allowed}
    forwarded.setdefault("model", "deepseek-chat")
    data = json.dumps(forwarded, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions",
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read(), resp.headers.get("content-type", "application/json")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("content-type", "application/json")


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()


class AppServer(BaseHTTPRequestHandler):
    server_version = "CandidateScreenerSQLite/1.0"

    @property
    def db_path(self) -> Path:
        return self.server.db_path  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def request_is_https(self) -> bool:
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def send_cookie(self, value: str, max_age: int = SESSION_TTL_SECONDS) -> None:
        cookie = f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        if self.request_is_https():
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)

    def clear_cookie(self) -> None:
        cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        if self.request_is_https():
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)

    def is_authenticated(self) -> bool:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return False
        morsel = cookie.get(SESSION_COOKIE)
        return bool(morsel and valid_session_value(morsel.value))

    def require_auth(self, parsed) -> bool:
        if parsed.path in {"/api/health", "/api/session", "/api/login"}:
            return True
        if self.is_authenticated():
            return True
        if parsed.path.startswith("/api/"):
            self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
        else:
            self.serve_login()
        return False

    def read_json_body(self) -> dict:
        raw_len = self.headers.get("Content-Length")
        length = int(raw_len or "0")
        if length > MAX_BODY_BYTES:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def store_key_from_path(self) -> str | None:
        parsed = urlparse(self.path)
        prefix = "/api/store/"
        if not parsed.path.startswith(prefix):
            return None
        return unquote(parsed.path[len(prefix) :])

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_json({"ok": True})
            return

        if parsed.path == "/api/session":
            self.send_json({"authenticated": self.is_authenticated(), "loginRequired": bool(configured_users())})
            return

        if not self.require_auth(parsed):
            return

        key = self.store_key_from_path()
        if key is not None:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT value, updated_at FROM kv_store WHERE key = ?",
                    (key,),
                ).fetchone()
            if row is None:
                self.send_json({"value": None})
            else:
                self.send_json({"value": row[0], "updatedAt": row[1]})
            return

        self.serve_static(parsed.path)

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        if not self.require_auth(parsed):
            return
        key = self.store_key_from_path()
        if key is None:
            self.send_text("Not found", HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self.read_json_body()
            value = payload.get("value")
            if not isinstance(value, str):
                raise ValueError("payload.value must be a string")
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO kv_store(key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (key, value),
                )
                conn.commit()
            self.send_json({"ok": True})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            try:
                users = configured_users()
                if not users:
                    self.send_json({"ok": False, "error": "服务端未配置 APP_USERS"}, HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                payload = self.read_json_body()
                username = str(payload.get("username") or "").strip()
                submitted = str(payload.get("password") or "")
                expected = users.get(username)
                if not expected or not hmac.compare_digest(submitted, expected):
                    self.send_json({"ok": False, "error": "账号或密码错误"}, HTTPStatus.UNAUTHORIZED)
                    return
                body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_cookie(make_session_value())
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if parsed.path == "/api/logout":
            body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.clear_cookie()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not self.require_auth(parsed):
            return

        if parsed.path == "/api/llm/deepseek":
            try:
                payload = self.read_json_body()
                status, body, content_type = call_deepseek(payload)
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if parsed.path != "/api/fetch-projects":
            self.send_text("Not found", HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self.read_json_body()
            urls = payload.get("urls")
            if not isinstance(urls, list):
                raise ValueError("payload.urls must be a list")
            expanded: list[str] = []
            seen: set[str] = set()
            for raw_url in urls[:8]:
                if not isinstance(raw_url, str):
                    continue
                url = raw_url.strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                expanded.append(url)
                for related in infer_related_urls(url):
                    if related not in seen:
                        seen.add(related)
                        expanded.append(related)
            results = [fetch_url_text(url) for url in expanded[:12]]
            self.send_json({"ok": True, "results": results})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if not self.require_auth(parsed):
            return
        key = self.store_key_from_path()
        if key is None:
            self.send_text("Not found", HTTPStatus.NOT_FOUND)
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM kv_store WHERE key = ?", (key,))
            conn.commit()
        self.send_json({"ok": True})

    def serve_login(self) -> None:
        target = ROOT / "login.html"
        if not target.exists():
            self.send_text("Login page not found", HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self, request_path: str) -> None:
        if request_path in ("/login", "/login.html"):
            return self.serve_login()
        if request_path in ("", "/"):
            target = ROOT / "index.html"
        else:
            rel = request_path.lstrip("/")
            target = (ROOT / rel).resolve()
            if ROOT not in target.parents and target != ROOT:
                self.send_text("Forbidden", HTTPStatus.FORBIDDEN)
                return
        if not target.exists() or not target.is_file():
            self.send_text("Not found", HTTPStatus.NOT_FOUND)
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    load_env_file(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Run the candidate screener with SQLite persistence.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    parser.add_argument("--db", default=str(DEFAULT_DB))
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    init_db(db_path)

    httpd = ThreadingHTTPServer((args.host, args.port), AppServer)
    httpd.db_path = db_path  # type: ignore[attr-defined]
    print(f"Serving {ROOT}")
    print(f"SQLite database: {db_path}")
    print(f"Open http://{args.host}:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")


if __name__ == "__main__":
    main()
