#!/usr/bin/env python3
"""
eapol_test Middleware API

802.1X EAP 認證測試中介層。
支援多個 RADIUS server，使用者透過名稱指定要測試的 server。
支援 PEAP 和 EAP-TTLS（tunneled EAP）以及傳統 RADIUS（PAP/CHAP/MSCHAP）。
"""

import base64
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial, wraps

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from flask import Flask, Response, jsonify, redirect, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.json.sort_keys = False

# ── 載入設定檔 ───────────────────────────────────────────────────

# 預設讀 app.py 旁邊的 config.json；EAPOL_CONFIG_PATH 為選配覆寫
# （測試套件用它指向 tests/config-test.json）
CONFIG_PATH = os.environ.get("EAPOL_CONFIG_PATH") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config.json")
if not os.path.isfile(CONFIG_PATH):
    raise RuntimeError(
        f"config file not found: {CONFIG_PATH} "
        "(cp config.example.json config.json, or set EAPOL_CONFIG_PATH)")
with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

SERVERS = CONFIG["servers"]
DEFAULT_SERVER = CONFIG.get("default_server", next(iter(SERVERS)))
DEFAULT_EAPOL_SSID = "eapol-test"


def _random_mac():
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) & 0xFE  # locally administered, unicast
    return "-".join(f"{b:02x}" for b in raw)


def _normalize_mac(value, field_name):
    if value is None or str(value).strip() == "":
        return _random_mac()
    mac = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{2}([-:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}", mac):
        raise RuntimeError(
            f"invalid {field_name} in config.json: expected aa-bb-cc-dd-ee-ff")
    return mac.replace(":", "-")


CALLED_STATION_MAC = _normalize_mac(
    CONFIG.get("called_station_mac"), "called_station_mac")
CALLING_STATION_MAC = _normalize_mac(
    CONFIG.get("calling_station_mac"), "calling_station_mac")

# ── 安全 / 限流設定 ──────────────────────────────────────────────

RAW_LOG_ENABLED = bool(
    CONFIG.get("raw_log", CONFIG.get("expose_config_used", False))
)

_RL_CFG = CONFIG.get("rate_limit", {})
RL_PER_IP_RPM = int(_RL_CFG.get("per_ip_requests_per_minute", 30))
RL_PER_IP_BATCH_PM = int(_RL_CFG.get("per_ip_batch_per_minute", 3))
GLOBAL_MAX_SUBPROCESSES = int(_RL_CFG.get("global_max_subprocesses", 50))
GLOBAL_MAX_BATCH_JOBS = int(_RL_CFG.get("global_max_batch_jobs", 5))
BATCH_MAX_WORKERS = int(CONFIG.get("batch_max_workers", 10))
TRUST_PROXY = bool(CONFIG.get("trust_proxy", False))
MAX_BODY_BYTES = int(CONFIG.get("max_body_bytes", 16 * 1024))  # 16 KB 預設夠帳密 + 選項
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

_WHITELIST_RAW = _RL_CFG.get("whitelist_ips", [])
WHITELIST_NETS = []
for entry in _WHITELIST_RAW:
    try:
        if "/" in entry:
            WHITELIST_NETS.append(ipaddress.ip_network(entry, strict=False))
        else:
            WHITELIST_NETS.append(ipaddress.ip_network(entry + "/32" if ":" not in entry else entry + "/128", strict=False))
    except ValueError:
        pass

if TRUST_PROXY:
    # Keep proxy-aware scheme/host handling, but resolve client IP ourselves.
    # This avoids Cloudflare -> nginx chains collapsing to a proxy IP.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)

# 全域資源 semaphore
SUBPROCESS_SEM = threading.BoundedSemaphore(GLOBAL_MAX_SUBPROCESSES)
BATCH_SEM = threading.BoundedSemaphore(GLOBAL_MAX_BATCH_JOBS)

# per-IP rate limit（簡易滑動視窗）
_rl_lock = threading.Lock()
_rl_hits = {}  # ip -> deque[timestamp] for general endpoints
_rl_batch = {}  # ip -> deque[timestamp] for batch endpoint
_RL_CLEANUP_INTERVAL = 60  # 至少間隔幾秒才掃一次
_last_rl_cleanup = 0.0

_rootca_cfg = CONFIG.get("rootca_fetch", {})
ROOTCA_FETCH_TIMEOUT = int(_rootca_cfg.get("timeout", 5))
ROOTCA_MAX_SIZE = int(_rootca_cfg.get("max_size_bytes", 262144))


def _first_valid_ip(value):
    if not value:
        return ""
    for part in str(value).split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return ""


def client_ip():
    if TRUST_PROXY:
        for header in ("CF-Connecting-IP", "True-Client-IP",
                       "X-Forwarded-For", "X-Real-IP"):
            ip = _first_valid_ip(request.headers.get(header, ""))
            if ip:
                return ip
    return request.remote_addr or "0.0.0.0"


def ip_is_whitelisted(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip_obj in net for net in WHITELIST_NETS)


def _sweep_rate_buckets(cutoff):
    """caller 必須持有 _rl_lock。掃所有 bucket，清掉過期 timestamps，
    刪除完全沒資料的 ip 鍵，避免 dict 被大量不同 IP 撐爆。"""
    for bucket in (_rl_hits, _rl_batch):
        dead = []
        for ip, dq in bucket.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(ip)
        for ip in dead:
            bucket.pop(ip, None)


def _rate_limit_check(ip, bucket, limit, window=60):
    global _last_rl_cleanup
    now = time.monotonic()
    cutoff = now - window
    with _rl_lock:
        if now - _last_rl_cleanup > _RL_CLEANUP_INTERVAL:
            _sweep_rate_buckets(cutoff)
            _last_rl_cleanup = now
        dq = bucket.setdefault(ip, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            retry = int(window - (now - dq[0])) + 1
            return False, retry
        dq.append(now)
        return True, 0


def rate_limited(is_batch=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = client_ip()
            if not ip_is_whitelisted(ip):
                bucket = _rl_batch if is_batch else _rl_hits
                limit = RL_PER_IP_BATCH_PM if is_batch else RL_PER_IP_RPM
                ok, retry = _rate_limit_check(ip, bucket, limit)
                if not ok:
                    resp = jsonify({"error": "rate limit exceeded", "retry_after": retry})
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ── EAP / RADIUS 定義 ───────────────────────────────────────────

PHASE2_OPTIONS = {
    "peap": {
        "mschapv2": "auth=MSCHAPV2",
        "gtc":      "auth=GTC",
        "md5":      "auth=MD5",
    },
    "ttls": {
        "pap":      "auth=PAP",
        "chap":     "auth=CHAP",
        "mschap":   "auth=MSCHAP",
        "mschapv2": "auth=MSCHAPV2",
        "eap-md5":      "autheap=MD5",
        "eap-gtc":      "autheap=GTC",
        "eap-mschapv2": "autheap=MSCHAPV2",
    },
}
PHASE2_DEFAULTS = {"peap": "mschapv2", "ttls": "pap"}
SUPPORTED_EAP_METHODS = list(PHASE2_OPTIONS.keys())
RADTEST_METHODS = ["pap", "chap", "mschap"]


# ── 參數取得（支援 JSON / form；敏感端點禁用 query string）────────

def get_param(key, default="", allow_query=True):
    data = request.get_json(silent=True)
    if data and key in data:
        val = data[key]
        if isinstance(val, bool):
            return val
        return str(val).strip() if val is not None else default
    if key in request.form:
        return request.form[key].strip()
    if allow_query and key in request.args:
        return request.args[key].strip()
    return default


def get_param_bool(key, default=True, allow_query=True):
    data = request.get_json(silent=True)
    if data and key in data:
        return bool(data[key])
    val = request.form.get(key)
    if val is None and allow_query:
        val = request.args.get(key)
    if val is None:
        return default
    return str(val).lower() in ("true", "1", "yes")


# ── 共用驗證 ─────────────────────────────────────────────────────

def validate_eap_request():
    username = get_param("username", allow_query=False)
    password = get_param("password", allow_query=False)
    # get_param 對 JSON bool 會原樣回傳，先確認是字串再 lower
    eap_method = get_param("eap_method", allow_query=False)
    eap_method = eap_method.lower() if isinstance(eap_method, str) else ""
    phase2 = get_param("phase2", allow_query=False)
    phase2 = phase2.lower() if isinstance(phase2, str) else ""
    anonymous_identity = get_param("anonymous_identity", allow_query=False)
    server_name = get_param("server", allow_query=False) or DEFAULT_SERVER

    errors = []
    if not username:
        errors.append("missing required parameter: username")
    if not password:
        errors.append("missing required parameter: password")
    if not eap_method:
        errors.append("missing required parameter: eap_method")
    elif eap_method not in PHASE2_OPTIONS:
        errors.append(f"unsupported EAP method: {eap_method}, available: {', '.join(SUPPORTED_EAP_METHODS)}")
    else:
        if not phase2:
            phase2 = PHASE2_DEFAULTS[eap_method]
        elif phase2 not in PHASE2_OPTIONS[eap_method]:
            errors.append(f"EAP {eap_method} does not support phase2={phase2}, available: {', '.join(sorted(PHASE2_OPTIONS[eap_method].keys()))}")
    if server_name not in SERVERS:
        errors.append(f"unknown server: {server_name}, available: {', '.join(sorted(SERVERS.keys()))}")

    return {
        "username": username, "password": password,
        "eap_method": eap_method, "phase2": phase2,
        "anonymous_identity": anonymous_identity,
        "server_name": server_name,
    }, errors


def server_supports(server_name, test_type):
    cfg = SERVERS.get(server_name, {})
    return test_type in cfg.get("types", ["eap", "non-eap"])


# ── eapol_test 核心 ──────────────────────────────────────────────

def _to_hex(s):
    return s.encode("utf-8").hex()


def server_ssid(server_cfg):
    return str(server_cfg.get("ssid") or DEFAULT_EAPOL_SSID)


def _wpa_quoted(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def eapol_radius_attributes(ssid):
    return [
        "-N", f"30:s:{CALLED_STATION_MAC}:{ssid}",
        "-N", f"31:s:{CALLING_STATION_MAC}",
    ]


def build_eapol_conf(identity, password, eap_method, phase2,
                     anonymous_identity="", ssid=DEFAULT_EAPOL_SSID):
    method_upper = eap_method.upper()
    phase2_str = PHASE2_OPTIONS[eap_method][phase2]
    lines = [
        "network={",
        f"    ssid={_wpa_quoted(ssid)}",
        "    key_mgmt=WPA-EAP",
        f"    eap={method_upper}",
        f"    identity={_to_hex(identity)}",
    ]
    if anonymous_identity:
        lines.append(f"    anonymous_identity={_to_hex(anonymous_identity)}")
    lines.append(f"    password={_to_hex(password)}")
    lines.append(f'    phase2="{phase2_str}"')
    if method_upper == "PEAP":
        lines.append('    phase1="peaplabel=0"')
    lines.append("}")
    return "\n".join(lines)


def mask_server_ip(output, server_cfg, server_name):
    addr = server_cfg["address"]
    port = str(server_cfg.get("port", 1812))
    secret = server_cfg.get("secret", "")
    output = output.replace(f"{addr}:{port}", f"<{server_name} Server IP>")
    output = output.replace(addr, f"<{server_name} Server IP>")
    if secret:
        output = output.replace(secret, "<SHARED_SECRET>")
    return output


def run_eapol_test(conf_content, server_cfg, server_name=""):
    tmp_dir = tempfile.mkdtemp(prefix="eapol_")
    uid = uuid.uuid4().hex[:8]
    conf_path = os.path.join(tmp_dir, f"eapol_{uid}.conf")
    cert_path = os.path.join(tmp_dir, f"server_cert_{uid}.pem")
    timeout = CONFIG.get("timeout", 30)
    if not SUBPROCESS_SEM.acquire(timeout=timeout + 10):
        return {"success": False, "return_code": -1,
                "output": "service busy: subprocess pool exhausted",
                "config_used": conf_content, "server_cert_pem": "",
                "_busy": True}
    try:
        with open(conf_path, "w") as f:
            f.write(conf_content)
        cmd = [
            CONFIG["eapol_test_path"], "-c", conf_path,
            "-a", server_cfg["address"],
            "-p", str(server_cfg.get("port", 1812)),
            "-s", server_cfg["secret"],
            "-t", str(timeout), "-o", cert_path,
        ]
        cmd.extend(eapol_radius_attributes(server_ssid(server_cfg)))
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout + 5)
        output = mask_server_ip(result.stdout + result.stderr,
                                server_cfg, server_name)
        server_cert_pem = ""
        if os.path.isfile(cert_path):
            with open(cert_path, "r") as f:
                server_cert_pem = f.read().strip()
        return {"success": "SUCCESS" in result.stdout,
                "return_code": result.returncode, "output": output,
                "config_used": conf_content, "server_cert_pem": server_cert_pem}
    except subprocess.TimeoutExpired:
        return {"success": False, "return_code": -1,
                "output": "eapol_test timed out",
                "config_used": conf_content, "server_cert_pem": ""}
    except Exception as e:
        return {"success": False, "return_code": -1,
                "output": f"execution error: {e}",
                "config_used": conf_content, "server_cert_pem": ""}
    finally:
        SUBPROCESS_SEM.release()
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ── radtest 核心 ─────────────────────────────────────────────────

def run_radtest(username, password, method, server_cfg, server_name=""):
    timeout = CONFIG.get("timeout", 30)
    addr = server_cfg["address"]
    port = str(server_cfg.get("port", 1812))
    secret = server_cfg["secret"]
    cmd = ["radtest", "-t", method, username, password,
           f"{addr}:{port}", "0", secret]
    if not SUBPROCESS_SEM.acquire(timeout=timeout + 10):
        return {"success": False, "return_code": -1,
                "output": "service busy: subprocess pool exhausted",
                "_busy": True}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout + 5)
        output = mask_server_ip(result.stdout + result.stderr,
                                server_cfg, server_name)
        success = "Access-Accept" in output and "Access-Reject" not in output
        return {"success": success, "return_code": result.returncode,
                "output": output}
    except subprocess.TimeoutExpired:
        return {"success": False, "return_code": -1,
                "output": "radtest timed out"}
    except Exception as e:
        return {"success": False, "return_code": -1,
                "output": f"execution error: {e}"}
    finally:
        SUBPROCESS_SEM.release()


def determine_radtest_result(output):
    if "Access-Reject" in output:
        return "FAILURE"
    if "Access-Accept" in output:
        return "SUCCESS"
    if "No reply" in output or "timed out" in output:
        return "TIMEOUT"
    return "ERROR"


# ── 輸出解析 ─────────────────────────────────────────────────────

_TLS_VERIFY_RE = re.compile(
    r"TLS: tls_verify_cb\b.*?depth=(\d+)\s+buf='(.+)'")
_CN_RE = re.compile(r'/CN=([^/]+)')
# 抓整個 PEM block（含 BEGIN/END 標頭）
_PEM_BLOCK_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL)
# 只抓 base64 本體（不含標頭）
_PEM_BODY_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----',
    re.DOTALL)


def parse_cert_subjects(output):
    certs, seen = [], set()
    for m in _TLS_VERIFY_RE.finditer(output):
        depth, subject = int(m.group(1)), m.group(2)
        if (depth, subject) in seen:
            continue
        seen.add((depth, subject))
        cn_match = _CN_RE.search(subject)
        certs.append({"depth": depth, "subject": subject,
                      "cn": cn_match.group(1) if cn_match else ""})
    certs.sort(key=lambda c: c["depth"])
    return certs


def parse_pem_certs(pem_text):
    if not pem_text:
        return []
    return [b.replace("\n", "").replace("\r", "").replace(" ", "")
            for b in _PEM_BODY_RE.findall(pem_text)]


# ── Root CA 追溯（AIA walking，含 SSRF 防護）───────────────────

ROOT_CA_MAX_DEPTH = 8
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
_system_ca_cache = None
_system_ca_lock = threading.Lock()

_SSRF_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + AWS/GCP metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
]
_SSRF_BLOCKED_HOSTS = {"localhost", "metadata.google.internal",
                       "metadata", "instance-data"}


def _is_blocked_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local \
            or ip_obj.is_multicast or ip_obj.is_reserved \
            or ip_obj.is_unspecified:
        return True
    return any(ip_obj in net for net in _SSRF_BLOCKED_NETS)


ROOTCA_MAX_REDIRECTS = 5

# 共用 TLS context：ssl.create_default_context() 每次都要重新載入系統
# CA bundle，AIA walking 一條鏈可能連續多個 HTTPS hop，快取起來避免
# 重複 I/O。SSLContext 的 wrap_socket 是 thread-safe 的。
_tls_ctx_lock = threading.Lock()
_tls_ctx = None


def _get_tls_context():
    global _tls_ctx
    if _tls_ctx is None:
        with _tls_ctx_lock:
            if _tls_ctx is None:
                # 標準安全預設：CERT_REQUIRED + check_hostname=True，
                # 載入系統 CA 信任庫
                _tls_ctx = ssl.create_default_context()
                _tls_ctx.check_hostname = True
                _tls_ctx.verify_mode = ssl.CERT_REQUIRED
    return _tls_ctx


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """明確只連到事先驗證過的 IP，不再由 socket 層做 DNS 解析。
    Host header 與一般連線行為與標準 HTTPConnection 一致。"""

    def __init__(self, host, pinned_ip, port=None, timeout=None):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TCP 只連到 pinned IP；TLS SNI 與憑證驗證仍使用原始 hostname。
    不會因為 pin IP 就關掉 TLS 驗證 —— wrap_socket 的 server_hostname
    走的是 self.host；預設 SSLContext 設定 check_hostname=True /
    verify_mode=CERT_REQUIRED。"""

    def __init__(self, host, pinned_ip, port=None, timeout=None, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
        )
        # self.host 保留為原始 hostname，做 SNI + hostname 比對
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self.host)


def _resolve_and_check(url):
    """驗證 URL 並解析 DNS；通過則回傳含 pinned IP 的 dict，否則回 None。
    後續 TCP 連線只會連到這裡 pin 住的 IP，杜絕 validate 與 connect
    之間 DNS 被換掉的 TOCTOU / DNS rebinding 視窗。"""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if not host or host in _SSRF_BLOCKED_HOSTS:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    public_ips = []
    for info in infos:
        ip = info[4][0]
        # 任何一個解析結果落在封鎖範圍 → 整個 URL 拒絕
        # （避免多筆 A record 混雜公開 IP 與私網 IP 的 rebinding）
        if _is_blocked_ip(ip):
            return None
        public_ips.append(ip)
    if not public_ips:
        return None
    path_query = parsed.path or "/"
    if parsed.query:
        path_query += "?" + parsed.query
    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "ip": public_ips[0],
        "path_query": path_query,
    }


def _validate_url_for_ssrf(url):
    """舊 API 包裝；僅回 bool。實際 pin 用的解析結果由 `_resolve_and_check`
    產生。保留此函式供外部呼叫 / 測試使用。"""
    return _resolve_and_check(url) is not None


def _pinned_fetch_once(url):
    """單一跳 fetch。連線只連到 `_resolve_and_check` 產出的 pinned IP；
    HTTPS 以原始 hostname 做 SNI / 憑證驗證。回傳：
      ('body', bytes)         — 200 OK
      ('redirect', abs_url)   — 3xx，urljoin 後的絕對 URL（下一跳需再驗）
      None                    — 被拒 / 失敗 / 過大
    """
    info = _resolve_and_check(url)
    if info is None:
        return None
    conn = None
    try:
        if info["scheme"] == "https":
            conn = _PinnedHTTPSConnection(
                host=info["host"], pinned_ip=info["ip"],
                port=info["port"], timeout=ROOTCA_FETCH_TIMEOUT,
                context=_get_tls_context(),
            )
        else:
            conn = _PinnedHTTPConnection(
                host=info["host"], pinned_ip=info["ip"],
                port=info["port"], timeout=ROOTCA_FETCH_TIMEOUT,
            )
        conn.request(
            "GET", info["path_query"],
            headers={"User-Agent": "eapol-middleware/1.0",
                     "Host": info["host"]},
        )
        resp = conn.getresponse()
        status = resp.status
        if status in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location")
            try:
                resp.read()
            except Exception:
                pass
            if not loc:
                return None
            return ("redirect", urllib.parse.urljoin(url, loc))
        if status != 200:
            return None
        buf = bytearray()
        remaining = ROOTCA_MAX_SIZE + 1
        while remaining > 0:
            chunk = resp.read(remaining)
            if not chunk:
                break
            buf.extend(chunk)
            remaining -= len(chunk)
        if len(buf) > ROOTCA_MAX_SIZE:
            return None
        return ("body", bytes(buf))
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _safe_fetch_url(url):
    """抓 URL；每一跳都重新做 scheme / host / DNS / IP SSRF 驗證並 pin IP；
    redirect 上限 ROOTCA_MAX_REDIRECTS。失敗一律回 None，不洩漏內部細節。"""
    current = url
    for _ in range(ROOTCA_MAX_REDIRECTS + 1):
        res = _pinned_fetch_once(current)
        if res is None:
            return None
        kind, value = res
        if kind == "body":
            return value
        # kind == "redirect"：下一輪會對新 URL 重做 _resolve_and_check，
        # 等同每跳重新 getaddrinfo + IP 檢查 + pin IP
        current = value
    return None  # redirect 次數超過上限


def _load_cert_any_format(data):
    """嘗試 PEM → DER → PKCS7(DER) → PKCS7(PEM)"""
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass
    try:
        certs = pkcs7.load_der_pkcs7_certificates(data)
        if certs:
            return certs[0]
    except Exception:
        pass
    try:
        certs = pkcs7.load_pem_pkcs7_certificates(data)
        if certs:
            return certs[0]
    except Exception:
        pass
    raise ValueError("unsupported certificate format")


def _cert_to_info(cert):
    parts = []
    for attr in cert.subject:
        name = attr.oid._name or attr.oid.dotted_string
        parts.append(f"{name}={attr.value}")
    subject = "/" + "/".join(parts)
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else ""
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"subject": subject, "cn": cn,
            "base64": base64.b64encode(der).decode()}


def _get_aia_ca_issuers_url(cert):
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return None
    for desc in ext.value:
        if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
            loc = desc.access_location
            if isinstance(loc, x509.UniformResourceIdentifier):
                return loc.value
    return None


def _fetch_cert(url):
    data = _safe_fetch_url(url)
    if data is None:
        return None
    try:
        return _load_cert_any_format(data)
    except Exception:
        return None


def _get_system_ca_map():
    global _system_ca_cache
    if _system_ca_cache is not None:
        return _system_ca_cache
    # 加鎖避免 batch + rootca 併發時多個 thread 同時解析整份 CA bundle
    with _system_ca_lock:
        if _system_ca_cache is not None:
            return _system_ca_cache
        result = {}
        try:
            with open(SYSTEM_CA_BUNDLE, "rb") as f:
                pem = f.read().decode(errors="ignore")
            for block in _PEM_BLOCK_RE.findall(pem):
                try:
                    c = x509.load_pem_x509_certificate(block.encode())
                    result[c.subject] = c
                except Exception:
                    pass
        except Exception:
            pass
        _system_ca_cache = result
        return result


def find_root_ca(leaf_cert):
    current = leaf_cert
    visited = set()
    ca_map = _get_system_ca_map()
    for _ in range(ROOT_CA_MAX_DEPTH):
        if current.issuer == current.subject:
            return current
        fp = current.fingerprint(hashes.SHA256())
        if fp in visited:
            return None
        visited.add(fp)
        if current.issuer in ca_map:
            current = ca_map[current.issuer]
            continue
        url = _get_aia_ca_issuers_url(current)
        if not url:
            return None
        nxt = _fetch_cert(url)
        if nxt is None:
            return None
        current = nxt
    return current if current.issuer == current.subject else None


def _load_pem_chain(pem_text):
    if not pem_text:
        return []
    certs, seen = [], set()
    for b in _PEM_BLOCK_RE.findall(pem_text):
        try:
            c = x509.load_pem_x509_certificate(b.encode())
        except Exception:
            continue
        fp = c.fingerprint(hashes.SHA256())
        if fp in seen:
            continue
        seen.add(fp)
        certs.append(c)
    return certs


def _order_chain_leaf_to_root(certs):
    if not certs:
        return []
    subj_map = {}
    for c in certs:
        subj_map.setdefault(c.subject, c)
    issuers = {c.issuer for c in certs if c.issuer != c.subject}
    leaves = [c for c in certs
              if c.subject not in issuers and c.issuer != c.subject]
    if not leaves:
        leaves = [certs[0]]
    ordered = [leaves[0]]
    visited = {leaves[0].subject}
    current = leaves[0]
    while current.issuer != current.subject and current.issuer in subj_map:
        nxt = subj_map[current.issuer]
        if nxt.subject in visited:
            break
        ordered.append(nxt)
        visited.add(nxt.subject)
        current = nxt
    for c in certs:
        if c.subject not in visited:
            ordered.append(c)
            visited.add(c.subject)
    return ordered


def find_root_ca_from_pem_chain(pem_text):
    try:
        certs = _load_pem_chain(pem_text)
        if not certs:
            return None
        for c in certs:
            if c.issuer == c.subject:
                return _cert_to_info(c)
        ordered = _order_chain_leaf_to_root(certs)
        root = find_root_ca(ordered[-1])
        return _cert_to_info(root) if root else None
    except Exception:
        return None


def parse_cert_chain_info(pem_text):
    ordered = _order_chain_leaf_to_root(_load_pem_chain(pem_text))
    return [_cert_to_info(c) for c in ordered]


def determine_auth_result(output):
    if "SUCCESS" in output:
        return "SUCCESS"
    if "EAPOL test timed out" in output:
        return "TIMEOUT"
    if ("CTRL-EVENT-EAP-FAILURE" in output
            or "EAP: Received EAP-Failure" in output
            or "Access-Reject" in output):
        return "FAILURE"
    return "ERROR"


# ── 安全 header / CSP ───────────────────────────────────────────

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

SENSITIVE_API_PREFIXES = ("/api/eapol-test", "/api/radtest", "/api/batch")


@app.errorhandler(413)
def _too_large(e):
    resp = jsonify({"error": "request body too large",
                    "max_bytes": MAX_BODY_BYTES})
    resp.status_code = 413
    return resp


@app.after_request
def set_security_headers(resp):
    ct = resp.headers.get("Content-Type", "")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    if ct.startswith("text/html"):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    if request.path.startswith(SENSITIVE_API_PREFIXES):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    return resp


# ── API Routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/batch")
def batch_page():
    return render_template("batch.html")


# ── Public plain-text endpoints (RFC 9309 robots, RFC 9116 security.txt) ──
# Rate-limit free (these are meant to be crawled / discovered) and not
# subject to the sensitive-API no-store header. A short cache is fine.

ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Allow: /batch\n"
    "Disallow: /api/\n"
)

SECURITY_TXT = (
    "Contact: mailto:noc@eduroam.tw\n"
    "Contact: mailto:roamingcenter@gms.ndhu.edu.tw\n"
    "Contact: tel:+886-3-890-6206\n"
    "Expires: 2027-04-20T00:00:00Z\n"
    "Preferred-Languages: zh-Hant, en\n"
    "# eduroam Taiwan Community Database\n"
    "# Taiwan Academic Network Roaming Center\n"
)


@app.route("/robots.txt")
def robots_txt():
    return Response(ROBOTS_TXT, mimetype="text/plain; charset=utf-8")


@app.route("/.well-known/security.txt")
def security_txt():
    return Response(SECURITY_TXT, mimetype="text/plain; charset=utf-8")


@app.route("/security.txt")
def security_txt_alias():
    # RFC 9116 mandates /.well-known/security.txt; redirect the bare path
    # so clients that try the legacy location still find it.
    return redirect("/.well-known/security.txt", code=301)


@app.route("/api/servers", methods=["GET"])
def list_servers():
    result = {}
    for name, cfg in SERVERS.items():
        result[name] = {
            "description": cfg.get("description", ""),
            "types": cfg.get("types", ["eap", "non-eap"]),
        }
    return jsonify({"servers": result, "default": DEFAULT_SERVER})


def _execute_eap_request():
    """共用的 EAP 端點前置流程：驗參數 → 檢查 server 支援 → 跑 eapol_test。
    回傳 (params, raw_result, error_response)；error_response 非 None 時
    直接回給 client。"""
    params, errors = validate_eap_request()
    if errors:
        return None, None, (jsonify({"error": errors}), 400)
    if not server_supports(params["server_name"], "eap"):
        return None, None, (
            jsonify({"error": f"server {params['server_name']} does not support EAP"}), 400)

    server_cfg = SERVERS[params["server_name"]]
    conf = build_eapol_conf(params["username"], params["password"],
                            params["eap_method"], params["phase2"],
                            params["anonymous_identity"],
                            server_ssid(server_cfg))
    raw = run_eapol_test(conf, server_cfg, params["server_name"])
    if raw.pop("_busy", False):
        return None, None, (jsonify({"error": "service busy"}), 503)
    return params, raw, None


@app.route("/api/eapol-test", methods=["POST"])
@rate_limited()
def eapol_test_endpoint():
    params, result, err = _execute_eap_request()
    if err:
        return err
    result["server"] = params["server_name"]
    if not RAW_LOG_ENABLED:
        # config_used (eapol_test conf) and output (raw stdout) are both
        # debug info and leak the same class of secrets (identity, ssid).
        # Gate them as a pair so flipping the switch is unambiguous.
        result.pop("config_used", None)
        result.pop("output", None)
    if get_param_bool("rootca", False, allow_query=False):
        result["root_ca"] = find_root_ca_from_pem_chain(
            result.get("server_cert_pem", ""))
    return jsonify(result), 200 if result["success"] else 401


@app.route("/api/eapol-test/structured", methods=["POST"])
@rate_limited()
def eapol_test_structured():
    params, raw, err = _execute_eap_request()
    if err:
        return err

    auth_result = determine_auth_result(raw["output"])
    server_certs = parse_cert_subjects(raw["output"])
    server_certs_b64 = parse_pem_certs(raw.get("server_cert_pem", ""))
    server_cert_chain = parse_cert_chain_info(raw.get("server_cert_pem", ""))

    structured = {
        "server": params["server_name"],
        "identity": params["username"],
        "anonymous_identity": params["anonymous_identity"],
        "eap_method": params["eap_method"],
        "phase2": params["phase2"],
        "result": auth_result,
        "server_certs": server_certs,
        "server_certs_base64": server_certs_b64,
        "server_cert_chain": server_cert_chain,
    }
    if RAW_LOG_ENABLED:
        # raw_output and config_used are paired debug info — only emit them
        # together so the operator gate has one obvious meaning.
        structured["raw_output"] = raw["output"]
        structured["config_used"] = raw.get("config_used", "")
    if get_param_bool("rootca", False, allow_query=False):
        structured["root_ca"] = find_root_ca_from_pem_chain(
            raw.get("server_cert_pem", ""))
    code = 200 if auth_result == "SUCCESS" else 504 if auth_result == "TIMEOUT" else 401
    return jsonify(structured), code


@app.route("/api/radtest", methods=["POST"])
@rate_limited()
def radtest_endpoint():
    username = get_param("username", allow_query=False)
    password = get_param("password", allow_query=False)
    method = (get_param("method", allow_query=False) or "").lower()
    server_name = get_param("server", allow_query=False) or DEFAULT_SERVER

    errors = []
    if not username:
        errors.append("missing required parameter: username")
    if not password:
        errors.append("missing required parameter: password")
    if not method:
        errors.append("missing required parameter: method")
    elif method not in RADTEST_METHODS:
        errors.append(f"unsupported method: {method}, available: {', '.join(RADTEST_METHODS)}")
    if server_name not in SERVERS:
        errors.append(f"unknown server: {server_name}")
    if errors:
        return jsonify({"error": errors}), 400
    if not server_supports(server_name, "non-eap"):
        return jsonify({"error": f"server {server_name} does not support non-EAP RADIUS"}), 400

    raw = run_radtest(username, password, method,
                      SERVERS[server_name], server_name)
    if raw.pop("_busy", False):
        return jsonify({"error": "service busy"}), 503
    result = determine_radtest_result(raw["output"])
    structured = {
        "server": server_name, "identity": username,
        "method": method, "result": result,
    }
    if RAW_LOG_ENABLED:
        structured["raw_output"] = raw["output"]
    code = 200 if result == "SUCCESS" else 504 if result == "TIMEOUT" else 401
    return jsonify(structured), code


@app.route("/api/batch", methods=["POST"])
@rate_limited(is_batch=True)
def batch_endpoint():
    username = get_param("username", allow_query=False)
    password = get_param("password", allow_query=False)
    anonymous_identity = get_param("anonymous_identity", allow_query=False)
    server_name = get_param("server", allow_query=False) or DEFAULT_SERVER
    parallel = get_param_bool("parallel", True, allow_query=False)
    want_rootca = get_param_bool("rootca", False, allow_query=False)

    errors = []
    if not username:
        errors.append("missing required parameter: username")
    if not password:
        errors.append("missing required parameter: password")
    if server_name not in SERVERS:
        errors.append(f"unknown server: {server_name}")
    if errors:
        return jsonify({"error": errors}), 400

    if not BATCH_SEM.acquire(blocking=False):
        resp = jsonify({"error": "batch queue full, try again later"})
        resp.status_code = 503
        resp.headers["Retry-After"] = "30"
        return resp

    try:
        server_cfg = SERVERS[server_name]
        eap_combos = [(eap, p2) for eap, pm in PHASE2_OPTIONS.items() for p2 in pm]

        def run_eap_one(eap, p2):
            conf = build_eapol_conf(username, password, eap, p2,
                                    anonymous_identity, server_ssid(server_cfg))
            raw = run_eapol_test(conf, server_cfg, server_name)
            raw.pop("_busy", None)
            result = determine_auth_result(raw["output"])
            certs = parse_cert_subjects(raw["output"])
            certs_b64 = parse_pem_certs(raw.get("server_cert_pem", ""))
            cert_cn = next((c["cn"] for c in certs if c["depth"] == 0), "")
            cert_b64 = certs_b64[-1] if certs_b64 else ""
            return {"type": "eap", "eap_method": eap, "phase2": p2,
                    "result": result, "server_cert_cn": cert_cn,
                    "server_cert_base64": cert_b64,
                    "_server_cert_pem": raw.get("server_cert_pem", "")}

        def run_rad_one(method):
            raw = run_radtest(username, password, method, server_cfg, server_name)
            raw.pop("_busy", None)
            result = determine_radtest_result(raw["output"])
            return {"type": "non-eap", "eap_method": "non-eap", "phase2": method,
                    "result": result, "server_cert_cn": "", "server_cert_base64": ""}

        tasks = []
        if server_supports(server_name, "eap"):
            tasks += [partial(run_eap_one, eap, p2) for eap, p2 in eap_combos]
        if server_supports(server_name, "non-eap"):
            tasks += [partial(run_rad_one, m) for m in RADTEST_METHODS]

        if parallel and len(tasks) > 1:
            workers = min(len(tasks), BATCH_MAX_WORKERS)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(t) for t in tasks]
                results = [f.result() for f in as_completed(futures)]
        else:
            results = [t() for t in tasks]

        type_order = {"non-eap": 0, "eap": 1}
        results.sort(key=lambda r: (type_order.get(r.get("type", "eap"), 1),
                                    r["eap_method"], r["phase2"]))

        if want_rootca:
            cache = {}
            for r in results:
                pem = r.pop("_server_cert_pem", "")
                if r.get("type") != "eap" or not pem:
                    r["root_ca"] = None
                    continue
                if pem not in cache:
                    cache[pem] = find_root_ca_from_pem_chain(pem)
                r["root_ca"] = cache[pem]
        else:
            for r in results:
                r.pop("_server_cert_pem", None)

        response = {"server": server_name, "identity": username,
                    "results": results}
        return jsonify(response)
    finally:
        BATCH_SEM.release()


@app.route("/api/supported-methods", methods=["GET"])
def supported_methods():
    methods = {}
    for eap, pm in PHASE2_OPTIONS.items():
        methods[eap] = {"phase2_options": sorted(pm.keys()),
                        "default_phase2": PHASE2_DEFAULTS[eap]}
    return jsonify({"methods": methods})


@app.route("/api/health", methods=["GET"])
def health():
    eapol_available = os.path.isfile(CONFIG["eapol_test_path"])
    return jsonify({
        "status": "ok" if eapol_available else "degraded",
        "eapol_test_available": eapol_available,
        "server_count": len(SERVERS),
        "default_server": DEFAULT_SERVER,
    })


if __name__ == "__main__":
    debug_mode = os.environ.get("EAPOL_DEBUG", "").strip().lower() in (
        "1", "true", "yes", "on"
    )
    print("=== eapol_test Middleware API ===")
    print(f"Listening on: {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    print(f"Servers ({len(SERVERS)}): {', '.join(SERVERS.keys())}")
    print(f"Debug mode: {'on' if debug_mode else 'off'}")
    app.run(host=CONFIG["listen_host"], port=CONFIG["listen_port"],
            debug=debug_mode, use_reloader=debug_mode)
