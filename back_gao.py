import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import urllib.parse
import ssl
import urllib.request
import urllib.error

from curl_cffi import requests

# ==========================================
# Cloudflare Temp Email API
# ==========================================


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key or key in os.environ:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"}:
                    value = value[1:-1]
                os.environ[key] = value
    except Exception:
        pass


_load_dotenv()

MAIL_DOMAIN =os.getenv("MAIL_DOMAIN", "")
MAIL_WORKER_BASE = os.getenv("MAIL_WORKER_BASE", "").rstrip("/")
MAIL_ADMIN_PASSWORD = os.getenv("MAIL_ADMIN_PASSWORD", "")
TOKEN_OUTPUT_DIR = os.getenv("TOKEN_OUTPUT_DIR", "").strip()
CLI_PROXY_AUTHS_DIR = os.getenv("CLI_PROXY_AUTHS_DIR", "").strip()


def _ssl_verify() -> bool:
    return True


def _skip_net_check() -> bool:
    return False


def get_email_and_token(proxies: Any = None) -> tuple:
    """生成随机前缀的自有域名邮箱"""
    prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{prefix}@{MAIL_DOMAIN}"
    return email, email



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


def get_oai_code(token: str, email: str, proxies: Any = None, seen_ids: set = None) -> str:
    """通过 Cloudflare Worker Admin API 轮询获取 OpenAI 验证码"""
    headers = {
        "x-admin-auth": MAIL_ADMIN_PASSWORD,
        "Content-Type": "application/json",
    }
    if seen_ids is None:
        seen_ids = set()
    print(f"[*] 正在等待邮箱 {email} 的验证码...", end="", flush=True)

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            res = requests.get(
                f"{MAIL_WORKER_BASE}/admin/mails",
                params={"limit": 5, "offset": 0, "address": email},
                headers=headers,
                proxies=proxies,
                impersonate="safari",
                verify=_ssl_verify(),
                timeout=15,
            )
            if res.status_code == 200:
                j = res.json()
                results = j.get("results") or []
                for mail in results:
                    mail_id = mail.get("id")
                    if mail_id in seen_ids:
                        continue
                    seen_ids.add(mail_id)
                    raw = mail.get("raw") or ""
                    content = raw
                    subj_match = re.search(
                        r"^Subject:\s*(.+)$", raw, re.MULTILINE
                    )
                    if subj_match:
                        content = subj_match.group(1) + "\n" + raw
                    code = _extract_otp_code(content)
                    if code:
                        print(" 抓到啦! 验证码:", code)
                        return code
        except Exception:
            pass

        time.sleep(3)

    print(" 超时，未收到验证码")
    return ""


def delete_temp_email(email: str, proxies: Any = None) -> None:
    """注册成功后删除临时邮箱地址及其所有邮件"""
    headers = {
        "x-admin-auth": MAIL_ADMIN_PASSWORD,
        "Content-Type": "application/json",
    }
    try:
        res = requests.get(
            f"{MAIL_WORKER_BASE}/admin/mails",
            params={"limit": 50, "offset": 0, "address": email},
            headers=headers,
            proxies=proxies,
            impersonate="safari",
            verify=_ssl_verify(),
            timeout=15,
        )
        if res.status_code == 200:
            for mail in (res.json().get("results") or []):
                mail_id = mail.get("id")
                if mail_id:
                    requests.delete(
                        f"{MAIL_WORKER_BASE}/admin/mails/{mail_id}",
                        headers=headers,
                        proxies=proxies,
                        impersonate="safari",
                        verify=_ssl_verify(),
                        timeout=10,
                    )
        print(f"[*] 临时邮箱 {email} 的邮件已清理")
    except Exception as e:
        print(f"[*] 清理临时邮箱时出错: {e}")


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


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
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        context = None
        if not _ssl_verify():
            context = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


def _post_with_retry(
    session: requests.Session,
    url: str,
    *,
    headers: Dict[str, Any],
    data: Any = None,
    json_body: Any = None,
    proxies: Any = None,
    timeout: int = 30,
    retries: int = 2,
) -> Any:
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            if json_body is not None:
                return session.post(
                    url,
                    headers=headers,
                    json=json_body,
                    proxies=proxies,
                    verify=_ssl_verify(),
                    timeout=timeout,
                )
            return session.post(
                url,
                headers=headers,
                data=data,
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=timeout,
            )
        except Exception as e:
            last_error = e
            if attempt >= retries:
                break
            time.sleep(2 * (attempt + 1))
    if last_error:
        raise last_error
    raise RuntimeError("Request failed without exception")


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
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
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ==========================================
# 核心注册逻辑
# ==========================================


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
    """生成符合 OpenAI 要求的随机强密码（大小写+数字+特殊字符）"""
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


def run(proxy: Optional[str]) -> tuple:
    proxies: Any = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    s = requests.Session(proxies=proxies, impersonate="safari")

    if not _skip_net_check():
        try:
            trace = s.get(
                "https://cloudflare.com/cdn-cgi/trace",
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=10,
            )
            trace = trace.text
            loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
            loc = loc_re.group(1) if loc_re else None
            print(f"[*] 当前 IP 所在地: {loc}")
            if loc == "CN" or loc == "HK":
                raise RuntimeError("检查代理哦w - 所在地不支持")
        except Exception as e:
            print(f"[Error] 网络连接检查失败: {e}")
            return None, None

    email, dev_token = get_email_and_token(proxies)
    if not email or not dev_token:
        return None, None
    print(f"[*] 成功获取临时邮箱与授权: {email}")
    masked = dev_token[:8] + "..." if dev_token else ""
    print(f"[*] 临时邮箱 JWT: {masked}")

    oauth = generate_oauth_url()
    url = oauth.auth_url

    try:
        resp = s.get(url, proxies=proxies, verify=True, timeout=15)
        did = s.cookies.get("oai-did")
        print(f"[*] Device ID: {did}")

        signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
        sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'

        sen_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body,
            proxies=proxies,
            impersonate="safari",
            verify=_ssl_verify(),
            timeout=15,
        )

        if sen_resp.status_code != 200:
            print(f"[Error] Sentinel 异常拦截，状态码: {sen_resp.status_code}")
            return None, None

        sen_token = sen_resp.json()["token"]
        sentinel = f'{{"p": "", "t": "", "c": "{sen_token}", "id": "{did}", "flow": "authorize_continue"}}'

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
            proxies=proxies,
            verify=_ssl_verify(),
        )
        signup_status = signup_resp.status_code
        print(f"[*] 提交注册表单状态: {signup_status}")

        if signup_status == 403:
            print("[Error] 提交注册表单返回 403，中断本次运行，将在10秒后重试...")
            return "retry_403", None
        if signup_status != 200:
            print("[Error] 提交注册表单失败，跳过本次流程")
            print(signup_resp.text)
            return None, None

        password = _generate_password()
        register_body = json.dumps({"password": password, "username": email})
        print(f"[*] 生成随机密码: {password[:4]}****")

        pwd_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=register_body,
            proxies=proxies,
            verify=_ssl_verify(),
        )
        print(f"[*] 提交注册(密码)状态: {pwd_resp.status_code}")
        if pwd_resp.status_code != 200:
            print(pwd_resp.text)
            return None, None

        try:
            register_json = pwd_resp.json()
            register_continue = register_json.get("continue_url", "")
            register_page = (register_json.get("page") or {}).get("type", "")
            print(f"[*] 注册响应 continue_url: {register_continue}")
            print(f"[*] 注册响应 page.type: {register_page}")
        except Exception:
            register_continue = ""
            register_page = ""
            print(f"[*] 注册响应(raw): {pwd_resp.text[:300]}")

        need_otp = "email-verification" in register_continue or "verify" in register_continue
        if not need_otp and register_page:
            need_otp = "verification" in register_page or "otp" in register_page

        if need_otp:
            print("[*] 需要邮箱验证，开始等待验证码...")

            if register_continue:
                otp_send_url = register_continue
                if not otp_send_url.startswith("http"):
                    otp_send_url = f"https://auth.openai.com{otp_send_url}"
                print(f"[*] 触发发送 OTP: {otp_send_url}")
                otp_send_resp = _post_with_retry(
                    s,
                    otp_send_url,
                    headers={
                        "referer": "https://auth.openai.com/create-account/password",
                        "accept": "application/json",
                        "content-type": "application/json",
                        "openai-sentinel-token": sentinel,
                    },
                    json_body={},
                    proxies=proxies,
                    timeout=30,
                    retries=2,
                )
                print(f"[*] OTP 发送状态: {otp_send_resp.status_code}")
                if otp_send_resp.status_code != 200:
                    print(otp_send_resp.text)

            processed_mails = set()
            code = ""
            for otp_attempt in range(5):
                if otp_attempt > 0:
                    print(f"\n[*] OTP 重试 {otp_attempt}/5，重新发送验证码...")
                    try:
                        _post_with_retry(
                            s,
                            "https://auth.openai.com/api/accounts/email-otp/resend",
                            headers={
                                "openai-sentinel-token": sentinel,
                                "content-type": "application/json",
                            },
                            json_body={},
                            proxies=proxies,
                            timeout=15,
                            retries=1,
                        )
                        time.sleep(2)
                    except Exception as e:
                        print(f"[*] 重发 OTP 异常: {e}")
                code = get_oai_code(token=dev_token, email=email, proxies=proxies, seen_ids=processed_mails)
                if code:
                    break
            if not code:
                print("[Error] 多次重试后仍未收到验证码，跳过")
                return None, None

            print("[*] 开始校验验证码...")
            code_resp = _post_with_retry(
                s,
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "openai-sentinel-token": sentinel,
                },
                json_body={"code": code},
                proxies=proxies,
                timeout=30,
                retries=2,
            )
            print(f"[*] 验证码校验状态: {code_resp.status_code}")
            if code_resp.status_code != 200:
                print(code_resp.text)
        else:
            print("[*] 密码注册无需邮箱验证，跳过 OTP 步骤")

        user_info = _random_user_info()
        print(f"[*] 开始创建账户 (昵称: {user_info['name']})...")
        create_account_resp = _post_with_retry(
            s,
            "https://auth.openai.com/api/accounts/create_account",
            headers={
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
            },
            json_body=user_info,
            proxies=proxies,
            timeout=30,
            retries=2,
        )
        create_account_status = create_account_resp.status_code
        print(f"[*] 账户创建状态: {create_account_status}")

        if create_account_status != 200:
            print(create_account_resp.text)
            return None, None

        print("[*] 账户创建完毕，执行静默重登录...")
        s.cookies.clear()

        oauth = generate_oauth_url()
        s.get(oauth.auth_url, proxies=proxies, verify=True, timeout=15)
        new_did = s.cookies.get("oai-did") or did

        sen_req_body2 = f'{{"p":"","id":"{new_did}","flow":"authorize_continue"}}'
        sen_resp2 = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body2,
            proxies=proxies,
            impersonate="safari",
            verify=_ssl_verify(),
            timeout=15,
        )
        sen_token2 = sen_resp2.json().get("token", "") if sen_resp2.status_code == 200 else ""
        sentinel2 = f'{{"p": "", "t": "", "c": "{sen_token2}", "id": "{new_did}", "flow": "authorize_continue"}}'

        _post_with_retry(
            s,
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "openai-sentinel-token": sentinel2,
                "content-type": "application/json",
            },
            json_body={"username": {"value": email, "kind": "email"}, "screen_hint": "login"},
            proxies=proxies,
        )

        pwd_login_resp = _post_with_retry(
            s,
            "https://auth.openai.com/api/accounts/password/verify",
            headers={
                "openai-sentinel-token": sentinel2,
                "content-type": "application/json",
            },
            json_body={"password": password},
            proxies=proxies,
        )
        print(f"[*] 密码登录状态: {pwd_login_resp.status_code}")

        if pwd_login_resp.status_code == 200:
            try:
                pwd_json = pwd_login_resp.json()
                pwd_page = (pwd_json.get("page") or {}).get("type", "")
                if "otp" in pwd_page or "verify" in str(pwd_json.get("continue_url", "")):
                    print("[*] 登录触发二次邮箱验证，等待验证码...")
                    code2 = ""
                    for otp2_attempt in range(5):
                        if otp2_attempt > 0:
                            print(f"\n[*] 二次 OTP 重试 {otp2_attempt}/5，重新发送...")
                            try:
                                _post_with_retry(
                                    s,
                                    "https://auth.openai.com/api/accounts/email-otp/resend",
                                    headers={
                                        "openai-sentinel-token": sentinel2,
                                        "content-type": "application/json",
                                    },
                                    json_body={},
                                    proxies=proxies,
                                    timeout=15,
                                    retries=1,
                                )
                                time.sleep(2)
                            except Exception as e:
                                print(f"[*] 重发异常: {e}")
                        code2 = get_oai_code(token=dev_token, email=email, proxies=proxies, seen_ids=processed_mails)
                        if code2:
                            break
                    if not code2:
                        print("[Error] 二次验证码获取失败")
                        return None, None
                    code2_resp = _post_with_retry(
                        s,
                        "https://auth.openai.com/api/accounts/email-otp/validate",
                        headers={
                            "openai-sentinel-token": sentinel2,
                            "content-type": "application/json",
                        },
                        json_body={"code": code2},
                        proxies=proxies,
                    )
                    print(f"[*] 二次验证码校验状态: {code2_resp.status_code}")
                    if code2_resp.status_code != 200:
                        print(code2_resp.text)
                        return None, None
            except Exception:
                pass

        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            print("[Error] 重登录后未能获取授权 Cookie")
            return None, None

        auth_json = {}
        raw_val = auth_cookie.strip()
        try:
            decoded_val = urllib.parse.unquote(raw_val)
            if decoded_val != raw_val:
                raw_val = decoded_val
        except Exception:
            pass
        for part in raw_val.split("."):
            decoded = _decode_jwt_segment(part)
            if isinstance(decoded, dict) and "workspaces" in decoded:
                auth_json = decoded
                break

        workspaces = auth_json.get("workspaces") or []
        if not workspaces:
            print("[Error] 重登录后 Cookie 里仍没有 workspace 信息")
            return None, None
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            print("[Error] 无法解析 workspace_id")
            return None, None

        select_body = f'{{"workspace_id":"{workspace_id}"}}'
        print("[*] 开始选择 workspace...")
        select_resp = _post_with_retry(
            s,
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=select_body,
            proxies=proxies,
            timeout=30,
            retries=2,
        )

        if select_resp.status_code != 200:
            print(f"[Error] 选择 workspace 失败，状态码: {select_resp.status_code}")
            print(select_resp.text)
            return None, None

        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()
        if not continue_url:
            print("[Error] workspace/select 响应里缺少 continue_url")
            return None, None

        try:
            select_data = select_resp.json()
            orgs = (select_data.get("data") or {}).get("orgs") or []
            if orgs:
                org_id = str((orgs[0] or {}).get("id") or "").strip()
                if org_id:
                    org_body = {"org_id": org_id}
                    projects = (orgs[0] or {}).get("projects") or []
                    if projects:
                        org_body["project_id"] = str((projects[0] or {}).get("id") or "").strip()
                    print(f"[*] 选择组织: {org_id}")
                    org_resp = _post_with_retry(
                        s,
                        "https://auth.openai.com/api/accounts/organization/select",
                        headers={
                            "content-type": "application/json",
                            "openai-sentinel-token": sentinel2,
                        },
                        json_body=org_body,
                        proxies=proxies,
                    )
                    if org_resp.status_code in [301, 302, 303, 307, 308]:
                        continue_url = org_resp.headers.get("Location", continue_url)
                    elif org_resp.status_code == 200:
                        try:
                            continue_url = org_resp.json().get("continue_url", continue_url)
                        except Exception:
                            pass
        except Exception as e:
            print(f"[*] 组织选择异常(非致命): {e}")

        current_url = continue_url
        for _ in range(15):
            final_resp = s.get(
                current_url,
                allow_redirects=False,
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=15,
            )

            if final_resp.status_code in [301, 302, 303, 307, 308]:
                next_url = urllib.parse.urljoin(
                    current_url, final_resp.headers.get("Location") or ""
                )
            elif final_resp.status_code == 200:
                if "consent_challenge=" in current_url:
                    c_resp = s.post(
                        current_url,
                        data={"action": "accept"},
                        allow_redirects=False,
                        proxies=proxies,
                        verify=_ssl_verify(),
                        timeout=15,
                    )
                    next_url = (
                        urllib.parse.urljoin(
                            current_url, c_resp.headers.get("Location") or ""
                        )
                        if c_resp.status_code in [301, 302, 303, 307, 308]
                        else ""
                    )
                else:
                    meta_match = re.search(
                        r'content=["\']?\d+;\s*url=([^"\'>\s]+)',
                        final_resp.text,
                        re.IGNORECASE,
                    )
                    next_url = (
                        urllib.parse.urljoin(current_url, meta_match.group(1))
                        if meta_match
                        else ""
                    )
                if not next_url:
                    break
            else:
                break

            if "code=" in next_url and "state=" in next_url:
                token_json = submit_callback_url(
                    callback_url=next_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )
                return token_json, password
            current_url = next_url
            time.sleep(0.5)

        print("[Error] 未能在重定向链中捕获到最终 Callback URL")
        return None, None

    except Exception as e:
        print(f"[Error] 运行时发生错误: {e}")
        return None, None


# ==========================================
# Token 检测与刷新
# ==========================================

AUTO_REGISTER_THRESHOLD = 10

_INVALID_ERRORS = {
    "account_deactivated", "invalid_api_key", "user_deactivated",
    "account_banned", "invalid_grant",
}


def _refresh_token(refresh_tok: str, proxies: Any = None) -> Dict[str, Any]:
    """用 refresh_token 换取新的 access_token"""
    try:
        resp = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_tok,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            impersonate="safari",
            verify=_ssl_verify(),
            proxies=proxies,
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            now = int(time.time())
            expires_in = max(int(data.get("expires_in", 3600)), 0)
            return {
                "ok": True,
                "access_token": data.get("access_token", ""),
                "refresh_token": data.get("refresh_token", refresh_tok),
                "id_token": data.get("id_token", ""),
                "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "expired": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + expires_in)),
            }
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_token(access_token: str, account_id: str = "", proxies: Any = None) -> Dict[str, Any]:
    """调用 ChatGPT API 测试 token 是否有效，返回 {valid, reason}"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    try:
        resp = requests.get(
            "https://chatgpt.com/backend-api/me",
            headers=headers,
            proxies=proxies,
            impersonate="safari",
            verify=_ssl_verify(),
            timeout=20,
        )
        if resp.status_code == 200:
            try:
                me = resp.json()
                if me.get("id"):
                    return {"valid": True, "reason": "正常"}
            except Exception:
                pass
            return {"valid": True, "reason": "正常"}

        try:
            err_data = resp.json()
            err_detail = err_data.get("detail", "")
            if isinstance(err_detail, dict):
                err_msg = err_detail.get("message", str(err_detail))
            else:
                err_msg = str(err_detail)
        except Exception:
            err_msg = resp.text[:200]

        if any(kw in err_msg.lower() for kw in ("deactivat", "banned", "suspended")):
            return {"valid": False, "reason": f"账号停用/无效 ({err_msg})"}
        if resp.status_code == 401:
            return {"valid": False, "reason": f"认证失败 (401)"}
        if resp.status_code == 403:
            return {"valid": False, "reason": f"禁止访问 (403: {err_msg})"}
        return {"valid": False, "reason": f"HTTP {resp.status_code}: {err_msg}"}
    except Exception as e:
        return {"valid": False, "reason": f"请求异常: {e}"}


def check_codex_tokens(proxies: Any = None) -> Dict[str, int]:
    """扫描 auths 目录下所有 codex token，检测状态并处理"""
    if not os.path.isdir(CLI_PROXY_AUTHS_DIR):
        print(f"[Error] 目录不存在: {CLI_PROXY_AUTHS_DIR}")
        return {"total": 0, "valid": 0, "refreshed": 0, "deleted": 0}

    files = sorted(f for f in os.listdir(CLI_PROXY_AUTHS_DIR) if f.startswith("codex-") and f.endswith(".json"))
    if not files:
        print("[*] 没有找到 codex token 文件")
        return {"total": 0, "valid": 0, "refreshed": 0, "deleted": 0}

    print(f"[*] 共发现 {len(files)} 个 codex token，开始检测...\n")
    valid_count = 0
    refreshed_count = 0
    deleted_count = 0

    for i, fname in enumerate(files, 1):
        fpath = os.path.join(CLI_PROXY_AUTHS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                token_data = json.loads(f.read())
        except Exception as e:
            print(f"  [{i}/{len(files)}] {fname} - 读取失败: {e}")
            continue

        email = token_data.get("email", fname)
        access_token = token_data.get("access_token", "")
        refresh_tok = token_data.get("refresh_token", "")
        account_id = token_data.get("account_id", "")

        is_expired = False
        claims = _jwt_claims_no_verify(access_token)
        exp_ts = claims.get("exp", 0)
        if exp_ts and int(time.time()) >= exp_ts:
            is_expired = True

        if is_expired:
            print(f"  [{i}/{len(files)}] {email} - access_token 已过期，尝试刷新...", end="")
            result = _refresh_token(refresh_tok, proxies=proxies)
            if result.get("ok"):
                token_data["access_token"] = result["access_token"]
                token_data["refresh_token"] = result["refresh_token"]
                token_data["id_token"] = result.get("id_token", token_data.get("id_token", ""))
                token_data["last_refresh"] = result["last_refresh"]
                token_data["expired"] = result["expired"]
                access_token = result["access_token"]
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(json.dumps(token_data, ensure_ascii=False, separators=(",", ":")))
                print(" 刷新成功!")
                refreshed_count += 1
            else:
                err = result.get("error", "")
                if any(kw in err.lower() for kw in ("deactivat", "invalid_grant", "banned")):
                    os.remove(fpath)
                    print(f" 刷新失败(账号无效)，已删除")
                    deleted_count += 1
                    continue
                else:
                    print(f" 刷新失败: {err}")
                    continue

        test = _test_token(access_token, account_id=account_id, proxies=proxies)
        if test["valid"]:
            print(f"  [{i}/{len(files)}] {email} - 状态正常 ✓")
            valid_count += 1
        else:
            reason = test["reason"]
            if "停用" in reason or "无效" in reason or "deactivat" in reason.lower():
                os.remove(fpath)
                print(f"  [{i}/{len(files)}] {email} - {reason}，已删除")
                deleted_count += 1
            elif "认证失败" in reason or "401" in reason:
                print(f"  [{i}/{len(files)}] {email} - {reason}，尝试刷新...", end="")
                result = _refresh_token(refresh_tok, proxies=proxies)
                if result.get("ok"):
                    token_data["access_token"] = result["access_token"]
                    token_data["refresh_token"] = result["refresh_token"]
                    token_data["id_token"] = result.get("id_token", token_data.get("id_token", ""))
                    token_data["last_refresh"] = result["last_refresh"]
                    token_data["expired"] = result["expired"]
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(json.dumps(token_data, ensure_ascii=False, separators=(",", ":")))
                    print(" 刷新成功!")
                    refreshed_count += 1
                    valid_count += 1
                else:
                    os.remove(fpath)
                    print(f" 刷新失败，已删除")
                    deleted_count += 1
            else:
                print(f"  [{i}/{len(files)}] {email} - {reason}")

    print(f"\n[*] 检测完毕: 有效 {valid_count} / 刷新 {refreshed_count} / 删除 {deleted_count} / 共 {len(files)}")
    return {"total": len(files), "valid": valid_count, "refreshed": refreshed_count, "deleted": deleted_count}


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--check", action="store_true", help="检测 auths 目录下 codex token 状态")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    args = parser.parse_args()

    if args.check:
        proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        stats = check_codex_tokens(proxies=proxies)
        valid_count = stats.get("valid", 0)
        if valid_count >= AUTO_REGISTER_THRESHOLD:
            print(f"[*] 当前可用 token {valid_count} 个，已达到阈值 {AUTO_REGISTER_THRESHOLD}，不执行自动注册")
            return
        need_count = AUTO_REGISTER_THRESHOLD - valid_count
        print(f"[*] 当前可用 token {valid_count} 个，低于阈值 {AUTO_REGISTER_THRESHOLD}，开始自动注册，目标补足 {need_count} 个")
        target_register_count = need_count
    else:
        target_register_count = None

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)

    count = 0
    print("[Info] Yasal's Seamless OpenAI Auto-Registrar Started for ZJH")
    print()
    print("=" * 60)
    print("  🔥 本脚本由 gaojilingjuli 出品")
    print("  📺 YouTube: https://www.youtube.com/@gaojilingjuli")
    print("  ⭐ 觉得好用？订阅频道支持一下！更多好用工具持续更新中~")
    print("=" * 60)
    print()

    while True:
        count += 1
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<"
        )

        try:
            token_json, password = run(args.proxy)

            if token_json == "retry_403":
                print("[Info] 检测到 403 错误，等待10秒后重试...")
                time.sleep(10)
                continue

            if token_json:
                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                    account_email = t_data.get("email", "")
                except Exception:
                    fname_email = "unknown"
                    account_email = ""

                file_name = f"token_{fname_email}_{int(time.time())}.json"
                if TOKEN_OUTPUT_DIR:
                    os.makedirs(TOKEN_OUTPUT_DIR, exist_ok=True)
                    file_name = os.path.join(TOKEN_OUTPUT_DIR, file_name)

                with open(file_name, "w", encoding="utf-8") as f:
                    f.write(token_json)

                print(f"[*] 成功! Token 已保存至: {file_name}")

                if os.path.isdir(CLI_PROXY_AUTHS_DIR) and account_email:
                    dest = os.path.join(CLI_PROXY_AUTHS_DIR, f"codex-{account_email}.json")
                    with open(dest, "w", encoding="utf-8") as df:
                        df.write(token_json)
                    print(f"[*] Token 已拷贝至: {dest}")
                    if os.path.exists(file_name):
                        os.remove(file_name)
                        print(f"[*] 本地 token 文件已删除: {file_name}")

                if account_email and password:
                    accounts_file = os.path.join(TOKEN_OUTPUT_DIR, "accounts.txt") if TOKEN_OUTPUT_DIR else "accounts.txt"
                    with open(accounts_file, "a", encoding="utf-8") as af:
                        af.write(f"{account_email}----{password}\n")
                    print(f"[*] 账号密码已追加至: {accounts_file}")

                if account_email:
                    proxies_cleanup = {"http": args.proxy, "https": args.proxy} if args.proxy else None
                    delete_temp_email(account_email, proxies=proxies_cleanup)
                if target_register_count is not None:
                    target_register_count -= 1
                    if target_register_count <= 0:
                        print(f"[*] 已补足到阈值 {AUTO_REGISTER_THRESHOLD}，停止自动注册")
                        break
            else:
                print("[-] 本次注册失败。")

        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[*] 休息 {wait_time} 秒...")
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
