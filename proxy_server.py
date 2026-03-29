"""
Temp Mail + OpenAI Auto-Register Proxy Server
-------------------------------------------
Flask 服务器，将 back_gao.py 的注册逻辑暴露为 HTTP 接口，供 index.html 调用。

依赖安装:
    pip install -r requirements.txt

直接运行:
    python proxy_server.py

Docker 运行:
    docker-compose up -d

本地开发:
    python proxy_server.py --port 5000 --proxy http://127.0.0.1:7890
"""

import argparse
import json
import os
import re
import sys
import time
import secrets
import hashlib
import base64
import random
import string
import threading
import urllib.parse
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from datetime import datetime
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, send_file, render_template_string, Response
from curl_cffi import requests as curl_requests


# ============================================================
# 全局配置（由启动参数和 .env 决定）
# ============================================================

def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key or key in os.environ:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                    value = value[1:-1]
                os.environ[key] = value
    except Exception:
        pass


_load_dotenv()

MAIL_DOMAIN = os.getenv("MAIL_DOMAIN", "")
MAIL_WORKER_BASE = os.getenv("MAIL_WORKER_BASE", "").rstrip("/")
MAIL_ADMIN_PASSWORD = os.getenv("MAIL_ADMIN_PASSWORD", "")
TOKEN_OUTPUT_DIR = os.getenv("TOKEN_OUTPUT_DIR", "").strip() or "/app/tokens"
CLI_PROXY_AUTHS_DIR = os.getenv("CLI_PROXY_AUTHS_DIR", "").strip()

CALLBACK_PORT = int(os.getenv("CALLBACK_PORT", "1455"))
CALLBACK_HOST = os.getenv("CALLBACK_HOST", "localhost")  # OAuth callback 主机名


# ============================================================
# Flask App
# ============================================================

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSON_SORT_KEYS"] = False

# CORS 支持（允许所有来源访问 API）
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Max-Age"] = "3600"
    return response


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /api/\n", 200


# ============================================================
# 辅助函数
# ============================================================

def _ssl_verify() -> bool:
    return True


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        context = ssl._create_unverified_context() if not _ssl_verify() else None
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}") from exc


def _extract_otp_code(content: str) -> str:
    if not content:
        return ""
    patterns = [
        r"Your ChatGPT code is\s*(\d{6})",
        r"ChatGPT code is\s*(\d{6})",
        r"verification code to continue:\s*(\d{6})",
        r"Subject:.*?(\d{6})",
    ]
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    fallback = re.search(r"(?<!\d)(\d{6})(?!\d)", content)
    return fallback.group(1) if fallback else ""


AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

_FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "David", "William", "Richard",
    "Joseph", "Thomas", "Christopher", "Daniel", "Matthew", "Anthony",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara",
    "Sarah", "Jessica", "Karen", "Emily", "Olivia", "Emma", "Sophia",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor",
    "Thomas", "Moore", "Jackson", "Martin", "Lee", "Harris", "Clark",
]


def _random_user_info() -> dict:
    name = f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}"
    year = random.randint(datetime.now().year - 45, datetime.now().year - 18)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return {"name": name, "birthdate": f"{year}-{month:02d}-{day:02d}"}


def _generate_password(length: int = 16) -> str:
    upper = random.choices(string.ascii_uppercase, k=2)
    lower = random.choices(string.ascii_lowercase, k=2)
    digits = random.choices(string.digits, k=2)
    specials = random.choices("!@#$%&*", k=2)
    rest_len = length - 8
    pool = string.ascii_letters + string.digits + "!@#$%&*"
    rest = random.choices(pool, k=rest_len)
    chars = upper + lower + digits + specials + rest
    random.shuffle(chars)
    return "".join(chars)


# ============================================================
# OAuth Callback 页面模板
# ============================================================

CALLBACK_PAGE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenAI 授权完成</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0f0f1a;
            color: #e2e8f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #1a1a2e;
            border: 1px solid #2d2d4a;
            border-radius: 20px;
            padding: 2.5rem;
            max-width: 500px;
            width: 90%;
            text-align: center;
        }
        .icon { font-size: 3rem; margin-bottom: 1rem; }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #9f67ff; }
        p { color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.5rem; line-height: 1.6; }
        .url-box {
            background: #000;
            border: 1px solid #2d2d4a;
            border-radius: 10px;
            padding: 0.8rem;
            font-family: 'Consolas', monospace;
            font-size: 0.75rem;
            color: #a3e635;
            word-break: break-all;
            max-height: 120px;
            overflow-y: auto;
            margin-bottom: 1rem;
            text-align: left;
        }
        .btn {
            display: inline-block;
            padding: 0.7rem 1.5rem;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            font-size: 0.9rem;
            text-decoration: none;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #7c3aed;
            color: #fff;
        }
        .btn-primary:hover { background: #9f67ff; transform: translateY(-1px); }
        .btn-secondary {
            background: #22223a;
            color: #94a3b8;
            border: 1px solid #2d2d4a;
            margin-left: 0.5rem;
        }
        .btn-secondary:hover { border-color: #7c3aed; color: #9f67ff; }
        .error { color: #ef4444; }
        .success { color: #4ade80; }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid rgba(159,103,255,0.3);
            border-top-color: #9f67ff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 1rem;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="card">
        <!-- 加载中 -->
        <div id="state-loading">
            <div class="spinner"></div>
            <h1>正在处理授权...</h1>
            <p>请稍候，正在完成 OpenAI 账号注册流程</p>
        </div>

        <!-- 成功 -->
        <div id="state-success" class="hidden">
            <div class="icon">🎉</div>
            <h1>授权成功!</h1>
            <p>OpenAI 账号注册完成，Token 已获取。<br>请返回管理面板查看结果。</p>
            <div class="url-box" id="token-preview"></div>
            <a href="{{ callback_host }}:5000" class="btn btn-primary">返回管理面板</a>
        </div>

        <!-- 错误 -->
        <div id="state-error" class="hidden">
            <div class="icon">❌</div>
            <h1 id="error-title">授权失败</h1>
            <p id="error-msg"></p>
            <div style="margin-top: 1rem;">
                <a href="{{ callback_host }}:5000" class="btn btn-primary">返回管理面板</a>
                <button onclick="window.close()" class="btn btn-secondary">关闭页面</button>
            </div>
        </div>
    </div>

    <script>
        const params = new URLSearchParams(window.location.search);
        const sessionId = sessionStorage.getItem('reg_session_id') || '';
        const callbackUrl = window.location.href;

        async function submitCallback() {
            try {
                const baseUrl = "{{ callback_host }}:5000";
                const res = await fetch(`${baseUrl}/api/register/callback/${sessionId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ callback_url: callbackUrl })
                });
                const data = await res.json();

                document.getElementById('state-loading').classList.add('hidden');

                if (res.ok) {
                    document.getElementById('state-success').classList.remove('hidden');
                    document.getElementById('token-preview').textContent =
                        'Token 已获取! 请返回管理面板查看完整内容。';
                } else {
                    document.getElementById('state-error').classList.remove('hidden');
                    document.getElementById('error-msg').textContent =
                        (data.error || '未知错误') + (data.state ? ' (状态: ' + data.state + ')' : '');
                }
            } catch (e) {
                document.getElementById('state-loading').classList.add('hidden');
                document.getElementById('state-error').classList.remove('hidden');
                document.getElementById('error-msg').textContent = '网络请求失败: ' + e.message;
            }
        }

        submitCallback();
    </script>
</body>
</html>
"""


# ============================================================
# 注册任务状态管理
# ============================================================

class RegisterTask:
    """单次注册任务"""

    def __init__(self, session_id: str, proxy: Optional[str] = None,
                 mail_domain: str = "", mail_worker_base: str = "",
                 mail_admin_password: str = "",
                 mail_output_dir: str = "", cli_auths_dir: str = "",
                 callback_host: str = "localhost"):
        self.session_id = session_id
        self.proxy = proxy
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

        self.mail_domain = mail_domain or MAIL_DOMAIN
        self.mail_worker_base = mail_worker_base or MAIL_WORKER_BASE
        self.mail_admin_password = mail_admin_password or MAIL_ADMIN_PASSWORD
        self.mail_output_dir = mail_output_dir or TOKEN_OUTPUT_DIR
        self.cli_auths_dir = cli_auths_dir or CLI_PROXY_AUTHS_DIR
        self.callback_host = callback_host

        self.state = "idle"
        self.status_text = "等待启动..."
        self.auth_url = ""
        self.oauth_state = ""
        self.code_verifier = ""
        self.callback_port = CALLBACK_PORT
        self.email = ""
        self.password = ""
        self.device_id = ""
        self.seen_mail_ids: set = set()
        self.log_lines: List[str] = []
        self.result_token = ""
        self.result_error = ""
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def get_redirect_uri(self) -> str:
        return f"http://{self.callback_host}:{self.callback_port}/auth/callback"

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        with self._lock:
            self.log_lines.append(line)
            if len(self.log_lines) > 500:
                self.log_lines = self.log_lines[-500:]
            self.status_text = msg

    def stop(self):
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "session_id": self.session_id,
                "state": self.state,
                "status": self.status_text,
                "auth_url": self.auth_url,
                "email": self.email,
                "callback_url_hint": self.get_redirect_uri(),
                "log": list(self.log_lines),
                "result_token": self.result_token,
                "result_error": self.result_error,
            }

    # ---- Temp Mail API ----

    def _create_email(self) -> bool:
        if not self.mail_worker_base or not self.mail_admin_password:
            prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            self.email = f"{prefix}@{self.mail_domain}"
            self.log(f"[*] 使用预设邮箱: {self.email}")
            return True

        try:
            prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            self.email = f"{prefix}@{self.mail_domain}"
            self.log(f"[*] 创建临时邮箱: {self.email}")
            headers = {
                "x-admin-auth": self.mail_admin_password,
                "Content-Type": "application/json",
            }
            res = curl_requests.post(
                f"{self.mail_worker_base}/admin/new_address",
                json={"enablePrefix": False, "name": prefix, "domain": self.mail_domain},
                headers=headers,
                proxies=self.proxies,
                impersonate="safari",
                verify=_ssl_verify(),
                timeout=15,
            )
            if res.status_code == 200:
                data = res.json()
                self.email = data.get("address", self.email)
                self.log(f"[*] 临时邮箱创建成功: {self.email}")
                return True
            else:
                self.log(f"[Error] 邮箱创建失败: {res.status_code} {res.text[:200]}")
                return False
        except Exception as e:
            self.log(f"[Error] 邮箱创建异常: {e}")
            return False

    def _poll_email_code(self) -> str:
        if not self.mail_worker_base or not self.mail_admin_password:
            self.log("[警告] 未配置邮件 API，无法自动获取验证码")
            return ""

        self.log("[*] 开始轮询邮箱验证码（最多 120 秒）...")
        headers = {
            "x-admin-auth": self.mail_admin_password,
            "Content-Type": "application/json",
        }

        for i in range(40):
            if self.is_stopped():
                return ""
            try:
                res = curl_requests.get(
                    f"{self.mail_worker_base}/admin/mails",
                    params={"limit": 5, "offset": 0, "address": self.email},
                    headers=headers,
                    proxies=self.proxies,
                    impersonate="safari",
                    verify=_ssl_verify(),
                    timeout=15,
                )
                if res.status_code == 200:
                    j = res.json()
                    results = j.get("results") or []
                    for mail in results:
                        mail_id = mail.get("id")
                        if mail_id in self.seen_mail_ids:
                            continue
                        self.seen_mail_ids.add(mail_id)
                        raw = mail.get("raw") or ""
                        subj_match = re.search(r"^Subject:\s*(.+)$", raw, re.MULTILINE)
                        content = (subj_match.group(1) + "\n" + raw) if subj_match else raw
                        code = _extract_otp_code(content)
                        if code:
                            self.log(f"[*] 抓取到验证码: {code}")
                            return code
            except Exception as e:
                self.log(f"[*] 轮询异常: {e}")
            time.sleep(3)

        self.log("[超时] 120 秒内未收到验证码")
        return ""

    # ---- OpenAI 注册核心 ----

    def _generate_oauth_url(self) -> str:
        state = _random_state()
        code_verifier = _pkce_verifier()
        code_challenge = _sha256_b64url_no_pad(code_verifier)
        redirect_uri = self.get_redirect_uri()

        params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": DEFAULT_SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        self.oauth_state = state
        self.code_verifier = code_verifier
        url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
        self.log(f"[*] OAuth redirect_uri: {redirect_uri}")
        return url

    def _post_with_retry(self, session, url, *, headers, json_body=None, data=None, timeout=30, retries=2):
        last_error = None
        for attempt in range(retries + 1):
            try:
                if json_body is not None:
                    return session.post(url, headers=headers, json=json_body,
                                        proxies=self.proxies, verify=_ssl_verify(), timeout=timeout)
                return session.post(url, headers=headers, data=data,
                                    proxies=self.proxies, verify=_ssl_verify(), timeout=timeout)
            except Exception as e:
                last_error = e
                if attempt >= retries:
                    break
                time.sleep(2 * (attempt + 1))
        if last_error:
            raise last_error
        raise RuntimeError("Request failed without exception")

    def _submit_callback(self, callback_url: str) -> str:
        if not callback_url:
            raise ValueError("callback_url 为空")

        candidate = callback_url.strip()
        if "://" not in candidate:
            if candidate.startswith("?"):
                candidate = f"http://localhost{candidate}"
            elif "=" in candidate:
                candidate = f"http://localhost/?{candidate}"
            else:
                candidate = f"http://{candidate}"

        parsed = urllib.parse.urlparse(candidate)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
        for key, values in fragment.items():
            if key not in query or not query[key] or not (query[key][0] or "").strip():
                query[key] = values

        def get1(k):
            v = query.get(k, [""])
            return (v[0] or "").strip()

        code = get1("code")
        state = get1("state")
        error = get1("error")

        if not error and not code:
            raise ValueError("callback 缺少 code")
        if error:
            raise RuntimeError(f"OAuth error: {error} {get1('error_description')}")
        if state != self.oauth_state:
            raise ValueError(f"state 不匹配: 期望 {self.oauth_state}, 收到 {state}")

        token_resp = _post_form(
            TOKEN_URL,
            {
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": self.get_redirect_uri(),
                "code_verifier": self.code_verifier,
            },
        )

        access_token = (token_resp.get("access_token") or "").strip()
        refresh_token = (token_resp.get("refresh_token") or "").strip()
        id_token = (token_resp.get("id_token") or "").strip()
        expires_in = _to_int(token_resp.get("expires_in"))

        claims = _jwt_claims_no_verify(id_token)
        email = str(claims.get("email") or "").strip()
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

        now = int(time.time())
        expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0)))
        now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        config = {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_id": account_id,
            "last_refresh": now_rfc3339,
            "email": email or self.email,
            "type": "codex",
            "expired": expired_rfc3339,
        }
        return json.dumps(config, ensure_ascii=False, separators=(",", ":"))

    def _run_registration(self):
        try:
            self.log("[*] 初始化会话...")
            self.log(f"[*] 使用邮箱: {self.mail_domain}")
            self.log(f"[*] Worker API: {self.mail_worker_base or '未配置（使用预设邮箱）'}")

            # --- 创建临时邮箱 ---
            if not self._create_email():
                raise RuntimeError("邮箱创建失败")
            time.sleep(1)

            # --- 生成 OAuth URL ---
            auth_url = self._generate_oauth_url()
            self.auth_url = auth_url
            self.log(f"[*] OAuth URL 已生成，请在浏览器中打开完成授权")
            self.log(f"[*] 授权后页面将跳转至: {self.get_redirect_uri()}")
            self.log("[*] 等待用户授权并提交 callback...")

            # 切换到等待 callback 状态
            with self._lock:
                self.state = "waiting_callback"

        except Exception as e:
            self.log(f"[Error] 初始化异常: {e}")
            with self._lock:
                self.state = "error"
                self.result_error = str(e)

    def resume_with_callback(self, callback_url: str):
        try:
            self.log("[*] 收到 callback，开始换取 token...")

            token_json = self._submit_callback(callback_url)
            self.result_token = token_json

            self.log("[*] Token 获取成功!")
            self.log("[*] 注册流程完成")

            # 保存 token
            self._save_token(token_json)

            with self._lock:
                self.state = "completed"

        except Exception as e:
            self.log(f"[Error] 处理 callback 异常: {e}")
            with self._lock:
                self.state = "error"
                self.result_error = str(e)

    def _save_token(self, token_json: str):
        try:
            t_data = json.loads(token_json)
            email_addr = t_data.get("email", "unknown").replace("@", "_")
            ts = int(time.time())
            fname_email = email_addr.replace("_at_", "@")

            # 保存主文件
            if self.mail_output_dir:
                os.makedirs(self.mail_output_dir, exist_ok=True)
                fname = os.path.join(self.mail_output_dir, f"token_{fname_email}_{ts}.json")
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(token_json)
                self.log(f"[*] Token 已保存: {fname}")

            # 追加到 accounts.txt
            accounts_file = os.path.join(self.mail_output_dir, "accounts.txt")
            with open(accounts_file, "a", encoding="utf-8") as af:
                pwd = t_data.get("_password_hint", "")
                af.write(f"{fname_email}----{pwd}\n")
            self.log(f"[*] 账号已追加: {accounts_file}")

            # 拷贝到 CLI auths 目录
            if self.cli_auths_dir and os.path.isdir(self.cli_auths_dir):
                dest = os.path.join(self.cli_auths_dir, f"codex-{fname_email}.json")
                with open(dest, "w", encoding="utf-8") as df:
                    df.write(token_json)
                self.log(f"[*] Token 已拷贝: {dest}")

        except Exception as e:
            self.log(f"[*] 保存文件时异常: {e}")


# ============================================================
# 任务存储
# ============================================================

tasks: Dict[str, RegisterTask] = {}
tasks_lock = threading.Lock()


def get_or_create_task(session_id: str, **kwargs) -> RegisterTask:
    with tasks_lock:
        if session_id in tasks:
            return tasks[session_id]
        task = RegisterTask(session_id=session_id, **kwargs)
        tasks[session_id] = task
        return task


# ============================================================
# API 路由
# ============================================================

@app.route("/")
def index():
    """返回前端页面"""
    static_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(static_path):
        return send_file(static_path)
    return jsonify({"ok": False, "message": "index.html not found"}), 404


@app.route("/api/status")
def api_status():
    cleanup_old_tasks()
    with tasks_lock:
        active = sum(1 for t in tasks.values() if t.state in ("running", "waiting_callback"))
        completed = sum(1 for t in tasks.values() if t.state == "completed")
        error = sum(1 for t in tasks.values() if t.state == "error")
    return jsonify({
        "ok": True,
        "mail_domain": MAIL_DOMAIN,
        "mail_worker_base": MAIL_WORKER_BASE,
        "mail_configured": bool(MAIL_WORKER_BASE and MAIL_ADMIN_PASSWORD),
        "callback_host": CALLBACK_HOST,
        "callback_port": CALLBACK_PORT,
        "active_tasks": active,
        "completed_tasks": completed,
        "error_tasks": error,
    })


@app.route("/api/register/start", methods=["POST"])
def api_register_start():
    body = request.get_json() or {}
    proxy = body.get("proxy", "")
    mail_domain = body.get("mail_domain", MAIL_DOMAIN)
    mail_worker_base = body.get("mail_worker_base", MAIL_WORKER_BASE).rstrip("/")
    mail_admin_password = body.get("mail_admin_password", MAIL_ADMIN_PASSWORD)
    mail_output_dir = body.get("mail_output_dir", TOKEN_OUTPUT_DIR)
    cli_auths_dir = body.get("cli_auths_dir", CLI_PROXY_AUTHS_DIR)
    callback_host = body.get("callback_host", CALLBACK_HOST)
    callback_port = body.get("callback_port", CALLBACK_PORT)

    session_id = secrets.token_urlsafe(16)
    task = get_or_create_task(
        session_id=session_id,
        proxy=proxy,
        mail_domain=mail_domain,
        mail_worker_base=mail_worker_base,
        mail_admin_password=mail_admin_password,
        mail_output_dir=mail_output_dir,
        cli_auths_dir=cli_auths_dir,
        callback_host=callback_host,
    )
    task.callback_port = callback_port

    def run_task():
        task._run_registration()

    t = threading.Thread(target=run_task, daemon=True)
    t.start()

    with tasks_lock:
        task.state = "running"

    return jsonify({
        "session_id": session_id,
        "auth_url": task.auth_url,
        "email": task.email,
        "callback_url_hint": task.get_redirect_uri(),
        "status": task.status_text,
        "state": task.state,
    })


@app.route("/api/register/poll/<session_id>")
def api_register_poll(session_id: str):
    with tasks_lock:
        task = tasks.get(session_id)
    if not task:
        return jsonify({"error": "session_id 不存在"}), 404
    return jsonify(task.get_status())


@app.route("/api/register/callback/<session_id>", methods=["POST"])
def api_register_callback(session_id: str):
    body = request.get_json() or {}
    callback_url = body.get("callback_url", "").strip()

    with tasks_lock:
        task = tasks.get(session_id)
    if not task:
        return jsonify({"error": "session_id 不存在"}), 404

    if task.state != "waiting_callback":
        return jsonify({
            "error": f"当前状态不允许提交 callback (state={task.state})",
            "state": task.state
        }), 400

    def handle():
        task.resume_with_callback(callback_url)

    threading.Thread(target=handle, daemon=True).start()
    return jsonify({"ok": True, "message": "正在处理 callback..."})


@app.route("/api/register/stop/<session_id>", methods=["POST"])
def api_register_stop(session_id: str):
    with tasks_lock:
        task = tasks.get(session_id)
    if not task:
        return jsonify({"error": "session_id 不存在"}), 404
    task.stop()
    with tasks_lock:
        task.state = "error"
        task.result_error = "用户主动停止"
    return jsonify({"ok": True})


@app.route("/api/register/delete/<session_id>", methods=["POST"])
def api_register_delete(session_id: str):
    with tasks_lock:
        if session_id in tasks:
            del tasks[session_id]
    return jsonify({"ok": True})


@app.route("/api/register/history")
def api_register_history():
    """返回最近所有任务历史"""
    with tasks_lock:
        result = [t.get_status() for t in tasks.values()]
    return jsonify({"tasks": result})


# ============================================================
# OAuth Callback 路由（监听在独立端口）
# ============================================================

# 注意：Flask 默认单端口运行。
# 如果需要同时监听 1455 端口处理 callback，
# 请用 docker-compose 映射端口，并在下方启用：
#
# @app_cb.route("/auth/callback")
# def oauth_callback():
#     callback_url = request.url
#     # 找到对应 session 并处理...
#
# app_cb = Flask(__name__)
# app_cb.register_blueprint(app, url_prefix=None)
# 如果你需要在容器内同时监听 1455 端口，
# 请在 docker-compose.yml 中添加第二个端口映射并创建独立进程。


def cleanup_old_tasks(max_age_seconds: int = 7200):
    """删除超过 max_age 秒的旧任务"""
    now = time.time()
    with tasks_lock:
        to_remove = [sid for sid, t in tasks.items() if t.state in ("completed", "error")]
        for sid in to_remove:
            del tasks[sid]


# ============================================================
# 启动
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Temp Mail + OpenAI Auto-Register Proxy Server")
    parser.add_argument("--port", type=int, default=5000, help="监听端口 (默认 5000)")
    parser.add_argument("--proxy", default=None, help="全局代理，如 http://127.0.0.1:7890")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    parser.add_argument("--callback-host", default=None,
                        help="OAuth callback 主机名，默认 localhost，"
                             "Docker 部署时设为容器 IP 或域名")
    parser.add_argument("--callback-port", type=int, default=1455,
                        help="OAuth callback 端口 (默认 1455)")
    parser.add_argument("--debug", action="store_true", help="Flask debug 模式")
    args = parser.parse_args()

    # 全局 callback 配置
    if args.callback_host:
        os.environ["CALLBACK_HOST"] = args.callback_host
    if args.callback_port:
        os.environ["CALLBACK_PORT"] = str(args.callback_port)

    print("=" * 60)
    print("  Temp Mail + OpenAI Auto-Register Proxy Server")
    print("=" * 60)
    print(f"  监听地址: http://{args.host}:{args.port}")
    print(f"  代理设置: {args.proxy or '无'}")
    print(f"  邮件 API: {MAIL_WORKER_BASE or '未配置'}")
    print(f"  邮件域名: {MAIL_DOMAIN}")
    print(f"  Callback: http://{args.callback_host or 'localhost'}:{args.callback_port}/auth/callback")
    print()
    print(f"  打开浏览器访问: http://localhost:{args.port}")
    print("=" * 60)

    # 运行时全局配置
    global CALLBACK_HOST, CALLBACK_PORT
    CALLBACK_HOST = args.callback_host or CALLBACK_HOST
    CALLBACK_PORT = args.callback_port

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
