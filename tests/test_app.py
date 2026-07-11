"""Tests for eapol-middleware (app.py).

Runs in-process via Flask's test_client. `run_eapol_test` / `run_radtest` are
monkey-patched so tests do NOT require a live RADIUS server.

Uses the EAPOL_CONFIG_PATH env var to point app.py at a writable temp config
file, so the real mounted config.json is never touched.
"""
import importlib
import ipaddress
import json
import os
import sys
import unittest

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

TEST_CONFIG_PATH = os.path.join(TESTS_DIR, "config-test.json")
os.environ["EAPOL_CONFIG_PATH"] = TEST_CONFIG_PATH


def base_config(**overrides):
    cfg = {
        "eapol_test_path": "/usr/bin/eapol_test",
        "timeout": 5,
        "default_server": "TEST",
        "servers": {
            "TEST": {
                "address": "127.0.0.1", "port": 1812,
                "secret": "secret123",
                "types": ["eap", "non-eap"],
            },
        },
    }
    cfg.update(overrides)
    return cfg


def load_app(config):
    with open(TEST_CONFIG_PATH, "w") as f:
        json.dump(config, f)
    if "app" in sys.modules:
        mod = importlib.reload(sys.modules["app"])
    else:
        import app as mod
    return mod


def fake_eapol(conf, server_cfg, server_name=""):
    return {
        "success": True, "return_code": 0,
        "output": "SUCCESS EAP-Success\n",
        "config_used": conf, "server_cert_pem": "",
    }


def fake_radtest(username, password, method, server_cfg, server_name=""):
    return {"output": "rad1 Access-Accept packet from host 127.0.0.1\n"}


class _Base(unittest.TestCase):
    def load(self, **kwargs):
        mod = load_app(base_config(**kwargs))
        mod.run_eapol_test = fake_eapol
        mod.run_radtest = fake_radtest
        return mod, mod.app.test_client()


class TestMethodGating(_Base):
    def test_get_sensitive_returns_405(self):
        _, client = self.load()
        for path in ["/api/eapol-test", "/api/eapol-test/structured",
                     "/api/radtest", "/api/batch"]:
            resp = client.get(path)
            self.assertEqual(resp.status_code, 405, path)

    def test_post_sensitive_not_405(self):
        _, client = self.load()
        resp = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        self.assertNotEqual(resp.status_code, 405)
        self.assertEqual(resp.status_code, 200)

    def test_public_endpoints_still_get(self):
        _, client = self.load()
        self.assertEqual(client.get("/api/health").status_code, 200)
        self.assertEqual(client.get("/api/servers").status_code, 200)
        self.assertEqual(client.get("/api/supported-methods").status_code, 200)
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/batch").status_code, 200)


class TestRawLog(_Base):
    def test_default_no_raw_log_structured(self):
        _, client = self.load()
        resp = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertNotIn("config_used", data)
        self.assertNotIn("raw_output", data)

    def test_default_no_raw_log_raw_endpoint(self):
        _, client = self.load()
        resp = client.post("/api/eapol-test", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertNotIn("config_used", data)
        self.assertNotIn("output", data)

    def test_default_no_raw_log_radtest(self):
        _, client = self.load()
        resp = client.post("/api/radtest", json={
            "username": "u", "password": "p", "method": "pap"})
        self.assertNotIn("raw_output", resp.get_json())

    def test_opt_in_structured(self):
        _, client = self.load(raw_log=True)
        resp = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertIn("config_used", data)
        self.assertIn("raw_output", data)

    def test_structured_uses_server_configured_ssid(self):
        _, client = self.load(raw_log=True, servers={
            "TEST": {
                "address": "127.0.0.1", "port": 1812,
                "secret": "secret123", "ssid": "eduroam",
                "types": ["eap", "non-eap"],
            },
        })
        resp = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertIn('ssid="eduroam"', data["config_used"])

    def test_opt_in_raw(self):
        _, client = self.load(raw_log=True)
        resp = client.post("/api/eapol-test", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertIn("config_used", data)
        self.assertIn("output", data)

    def test_opt_in_radtest(self):
        _, client = self.load(raw_log=True)
        resp = client.post("/api/radtest", json={
            "username": "u", "password": "p", "method": "pap"})
        self.assertIn("raw_output", resp.get_json())

    def test_legacy_config_name_still_supported(self):
        _, client = self.load(expose_config_used=True)
        resp = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        data = resp.get_json()
        self.assertIn("config_used", data)
        self.assertIn("raw_output", data)


class TestServersLeak(_Base):
    def test_no_ip_secret_in_servers(self):
        _, client = self.load()
        text = json.dumps(client.get("/api/servers").get_json())
        self.assertNotIn("127.0.0.1", text)
        self.assertNotIn("secret123", text)
        self.assertNotIn("1812", text)


class TestSecurityHeaders(_Base):
    def test_html_has_full_header_set(self):
        _, client = self.load()
        r = client.get("/")
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.headers.get("Referrer-Policy"), "no-referrer")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")
        csp = r.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("form-action 'self'", csp)

    def test_sensitive_api_nostore_no_csp(self):
        _, client = self.load()
        r = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")
        # CSP is for HTML only
        self.assertNotIn("Content-Security-Policy", r.headers)


class TestRateLimit(_Base):
    def test_per_ip_429_after_threshold(self):
        _, client = self.load(rate_limit={
            "per_ip_requests_per_minute": 3,
            "whitelist_ips": [],
        })
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        for _ in range(3):
            self.assertNotEqual(
                client.post("/api/eapol-test/structured", json=body).status_code,
                429)
        r = client.post("/api/eapol-test/structured", json=body)
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)
        data = r.get_json()
        self.assertIn("retry_after", data)

    def test_batch_has_separate_bucket(self):
        _, client = self.load(rate_limit={
            "per_ip_requests_per_minute": 100,
            "per_ip_batch_per_minute": 1,
            "whitelist_ips": [],
        })
        body = {"username": "u", "password": "p"}
        self.assertNotEqual(client.post("/api/batch", json=body).status_code, 429)
        self.assertEqual(client.post("/api/batch", json=body).status_code, 429)

    def test_whitelist_exact_ip_bypass(self):
        _, client = self.load(rate_limit={
            "per_ip_requests_per_minute": 1,
            "whitelist_ips": ["127.0.0.1/32"],
        })
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        for _ in range(5):
            self.assertNotEqual(
                client.post("/api/eapol-test/structured", json=body).status_code,
                429)

    def test_whitelist_cidr_bypass(self):
        _, client = self.load(rate_limit={
            "per_ip_requests_per_minute": 1,
            "whitelist_ips": ["127.0.0.0/8"],
        })
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        for _ in range(5):
            self.assertNotEqual(
                client.post("/api/eapol-test/structured", json=body).status_code,
                429)

    def test_nonwhitelist_ip_limited(self):
        _, client = self.load(
            trust_proxy=True,
            rate_limit={
                "per_ip_requests_per_minute": 2,
                "whitelist_ips": ["127.0.0.1/32"],
            },
        )
        headers = {"X-Forwarded-For": "203.0.113.42"}
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        for _ in range(2):
            self.assertNotEqual(
                client.post("/api/eapol-test/structured",
                            headers=headers, json=body).status_code, 429)
        r = client.post("/api/eapol-test/structured",
                        headers=headers, json=body)
        self.assertEqual(r.status_code, 429)


class TestTrustProxy(_Base):
    def test_trust_proxy_false_ignores_xff(self):
        _, client = self.load(
            trust_proxy=False,
            rate_limit={
                "per_ip_requests_per_minute": 1,
                "whitelist_ips": ["127.0.0.1/32"],
            },
        )
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        # Spoofed XFF must be ignored → stays 127.0.0.1, whitelisted
        for _ in range(5):
            self.assertNotEqual(
                client.post("/api/eapol-test/structured",
                            headers={"X-Forwarded-For": "203.0.113.42"},
                            json=body).status_code, 429)

    def test_trust_proxy_true_honors_xff(self):
        _, client = self.load(
            trust_proxy=True,
            rate_limit={
                "per_ip_requests_per_minute": 1,
                "whitelist_ips": ["127.0.0.1/32"],
            },
        )
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        r1 = client.post("/api/eapol-test/structured",
                         headers={"X-Forwarded-For": "203.0.113.42"},
                         json=body)
        self.assertNotEqual(r1.status_code, 429)
        r2 = client.post("/api/eapol-test/structured",
                         headers={"X-Forwarded-For": "203.0.113.42"},
                         json=body)
        self.assertEqual(r2.status_code, 429)

    def test_trust_proxy_prefers_cf_connecting_ip(self):
        _, client = self.load(
            trust_proxy=True,
            rate_limit={
                "per_ip_requests_per_minute": 1,
                "whitelist_ips": [],
            },
        )
        body = {"username": "u", "password": "p",
                "eap_method": "peap", "phase2": "mschapv2"}
        headers = {
            "CF-Connecting-IP": "198.51.100.24",
            "X-Forwarded-For": "203.0.113.42, 172.68.1.10",
        }
        r1 = client.post("/api/eapol-test/structured", headers=headers, json=body)
        self.assertNotEqual(r1.status_code, 429)
        r2 = client.post("/api/eapol-test/structured", headers=headers, json=body)
        self.assertEqual(r2.status_code, 429)

    def test_trust_proxy_falls_back_to_x_real_ip(self):
        mod, _ = self.load(trust_proxy=True)
        with mod.app.test_request_context(
                "/api/health", headers={"X-Real-IP": "198.51.100.11"}):
            self.assertEqual(mod.client_ip(), "198.51.100.11")


class TestSSRF(_Base):
    def test_safe_fetch_blocks_localhost_and_private(self):
        mod, _ = self.load()
        for url in ["http://localhost/x", "http://127.0.0.1/x",
                    "http://127.1.2.3/x", "http://10.0.0.1/x",
                    "http://172.16.0.1/x", "http://192.168.1.1/x",
                    "http://169.254.169.254/latest/meta-data",
                    "http://metadata.google.internal/",
                    "http://metadata/",
                    "http://[::1]/x"]:
            self.assertIsNone(mod._safe_fetch_url(url), url)

    def test_safe_fetch_blocks_non_http_scheme(self):
        mod, _ = self.load()
        for url in ["file:///etc/passwd", "ftp://example.com/",
                    "gopher://example.com/", "", "javascript:alert(1)"]:
            self.assertIsNone(mod._safe_fetch_url(url), url)

    def test_is_blocked_ip(self):
        mod, _ = self.load()
        for ip in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
                   "169.254.169.254", "100.64.0.1", "::1", "fe80::1",
                   "fc00::1", "0.0.0.0"]:
            self.assertTrue(mod._is_blocked_ip(ip), ip)
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"]:
            self.assertFalse(mod._is_blocked_ip(ip), ip)
        self.assertTrue(mod._is_blocked_ip("not-an-ip"))


class TestConfigDefaults(_Base):
    def test_missing_optional_keys_defaults(self):
        mod, _ = self.load()
        self.assertFalse(mod.RAW_LOG_ENABLED)
        self.assertFalse(mod.TRUST_PROXY)
        self.assertEqual(mod.RL_PER_IP_RPM, 30)
        self.assertEqual(mod.RL_PER_IP_BATCH_PM, 3)
        self.assertEqual(mod.GLOBAL_MAX_SUBPROCESSES, 50)
        self.assertEqual(mod.GLOBAL_MAX_BATCH_JOBS, 5)
        self.assertEqual(mod.BATCH_MAX_WORKERS, 10)
        self.assertEqual(mod.WHITELIST_NETS, [])
        self.assertEqual(mod.ROOTCA_FETCH_TIMEOUT, 5)
        self.assertEqual(mod.ROOTCA_MAX_SIZE, 262144)
        self.assertRegex(
            mod.CALLED_STATION_MAC,
            r"^[0-9a-f]{2}(-[0-9a-f]{2}){5}$")
        self.assertRegex(
            mod.CALLING_STATION_MAC,
            r"^[0-9a-f]{2}(-[0-9a-f]{2}){5}$")

    def test_station_macs_configured_and_normalized(self):
        mod, _ = self.load(
            called_station_mac="AA:BB:CC:DD:EE:FF",
            calling_station_mac="02-00-00-00-00-01",
        )
        self.assertEqual(mod.CALLED_STATION_MAC, "aa-bb-cc-dd-ee-ff")
        self.assertEqual(mod.CALLING_STATION_MAC, "02-00-00-00-00-01")

    def test_invalid_cidr_skipped(self):
        mod, _ = self.load(rate_limit={
            "whitelist_ips": ["not-an-ip", "999.0.0.1", "127.0.0.1/32", ""],
        })
        self.assertEqual(len(mod.WHITELIST_NETS), 1)

    def test_bare_ip_treated_as_single_host(self):
        mod, _ = self.load(rate_limit={
            "whitelist_ips": ["192.168.1.5", "2001:db8::1"],
        })
        self.assertEqual(len(mod.WHITELIST_NETS), 2)
        self.assertTrue(mod.ip_is_whitelisted("192.168.1.5"))
        self.assertFalse(mod.ip_is_whitelisted("192.168.1.6"))
        self.assertTrue(mod.ip_is_whitelisted("2001:db8::1"))

    def test_cidr_whitelist_matches_range(self):
        mod, _ = self.load(rate_limit={"whitelist_ips": ["10.0.0.0/8"]})
        self.assertTrue(mod.ip_is_whitelisted("10.0.0.1"))
        self.assertTrue(mod.ip_is_whitelisted("10.255.255.254"))
        self.assertFalse(mod.ip_is_whitelisted("11.0.0.1"))

    def test_full_custom_config(self):
        mod, _ = self.load(
            raw_log=True,
            trust_proxy=True,
            batch_max_workers=3,
            rate_limit={
                "per_ip_requests_per_minute": 7,
                "per_ip_batch_per_minute": 2,
                "global_max_subprocesses": 20,
                "global_max_batch_jobs": 2,
                "whitelist_ips": ["10.0.0.0/8"],
            },
            rootca_fetch={"timeout": 3, "max_size_bytes": 65536},
        )
        self.assertTrue(mod.RAW_LOG_ENABLED)
        self.assertTrue(mod.TRUST_PROXY)
        self.assertEqual(mod.RL_PER_IP_RPM, 7)
        self.assertEqual(mod.RL_PER_IP_BATCH_PM, 2)
        self.assertEqual(mod.GLOBAL_MAX_SUBPROCESSES, 20)
        self.assertEqual(mod.GLOBAL_MAX_BATCH_JOBS, 2)
        self.assertEqual(mod.BATCH_MAX_WORKERS, 3)
        self.assertEqual(mod.ROOTCA_FETCH_TIMEOUT, 3)
        self.assertEqual(mod.ROOTCA_MAX_SIZE, 65536)

    def test_server_types_filter(self):
        cfg = base_config(servers={
            "EAP_ONLY": {"address": "127.0.0.1", "port": 1812, "secret": "s",
                         "types": ["eap"]},
            "RAD_ONLY": {"address": "127.0.0.1", "port": 1812, "secret": "s",
                         "types": ["non-eap"]},
        })
        cfg["default_server"] = "EAP_ONLY"
        mod = load_app(cfg)
        mod.run_eapol_test = fake_eapol
        mod.run_radtest = fake_radtest
        client = mod.app.test_client()
        r = client.post("/api/radtest", json={
            "username": "u", "password": "p",
            "method": "pap", "server": "EAP_ONLY"})
        self.assertEqual(r.status_code, 400)
        r = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2", "server": "RAD_ONLY"})
        self.assertEqual(r.status_code, 400)

    def test_unknown_server(self):
        _, client = self.load()
        r = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2", "server": "nope"})
        self.assertEqual(r.status_code, 400)


class TestParamValidation(_Base):
    def test_missing_required_400(self):
        _, client = self.load()
        self.assertEqual(
            client.post("/api/eapol-test/structured", json={}).status_code,
            400)
        self.assertEqual(
            client.post("/api/radtest", json={}).status_code,
            400)
        self.assertEqual(
            client.post("/api/batch", json={}).status_code,
            400)

    def test_sensitive_ignores_query_string(self):
        _, client = self.load()
        qs = "?username=u&password=p&eap_method=peap&phase2=mschapv2"
        r = client.post("/api/eapol-test/structured" + qs)
        self.assertEqual(r.status_code, 400)

    def test_unsupported_eap_method(self):
        _, client = self.load()
        r = client.post("/api/eapol-test/structured", json={
            "username": "u", "password": "p",
            "eap_method": "xyz", "phase2": "mschapv2"})
        self.assertEqual(r.status_code, 400)


class TestBatchLimits(_Base):
    def test_batch_queue_full_returns_503(self):
        mod, client = self.load(rate_limit={
            "global_max_batch_jobs": 1,
            "per_ip_batch_per_minute": 100,
        })
        acquired = mod.BATCH_SEM.acquire(blocking=False)
        self.assertTrue(acquired)
        try:
            r = client.post("/api/batch", json={"username": "u", "password": "p"})
            self.assertEqual(r.status_code, 503)
            self.assertIn("Retry-After", r.headers)
        finally:
            mod.BATCH_SEM.release()

    def test_batch_max_workers_bounded(self):
        mod, _ = self.load(batch_max_workers=2)
        self.assertEqual(mod.BATCH_MAX_WORKERS, 2)


class TestErrorShape(_Base):
    def test_error_is_list_on_400(self):
        _, client = self.load()
        r = client.post("/api/eapol-test/structured", json={})
        self.assertEqual(r.status_code, 400)
        data = r.get_json()
        self.assertIn("error", data)
        self.assertIsInstance(data["error"], list)


class TestBodySizeLimit(_Base):
    def test_oversized_body_returns_413(self):
        _, client = self.load(max_body_bytes=1024)
        big = {"username": "u", "password": "p",
               "eap_method": "peap", "phase2": "mschapv2",
               "junk": "x" * 4096}
        r = client.post("/api/eapol-test", json=big)
        self.assertEqual(r.status_code, 413)
        data = r.get_json()
        self.assertIn("error", data)
        self.assertEqual(data.get("max_bytes"), 1024)

    def test_normal_body_not_413(self):
        _, client = self.load(max_body_bytes=16384)
        r = client.post("/api/eapol-test", json={
            "username": "u", "password": "p",
            "eap_method": "peap", "phase2": "mschapv2",
        })
        self.assertNotEqual(r.status_code, 413)

    def test_default_limit_is_16kb(self):
        mod, _ = self.load()
        self.assertEqual(mod.MAX_BODY_BYTES, 16 * 1024)
        self.assertEqual(mod.app.config["MAX_CONTENT_LENGTH"], 16 * 1024)


class TestRateLimitCleanup(_Base):
    def test_empty_buckets_are_pruned(self):
        mod, _ = self.load(rate_limit={"per_ip_requests_per_minute": 5})
        # populate several IPs
        from collections import deque
        now = 1000.0
        old = now - 120  # older than 60s window
        for i in range(50):
            mod._rl_hits["10.0.0." + str(i)] = deque([old])
            mod._rl_batch["10.0.0." + str(i)] = deque([old])
        # force a sweep by calling cleanup directly with a fresh cutoff
        mod._sweep_rate_buckets(cutoff=now - 60)
        self.assertEqual(len(mod._rl_hits), 0)
        self.assertEqual(len(mod._rl_batch), 0)

    def test_active_buckets_kept(self):
        mod, _ = self.load()
        from collections import deque
        now = 1000.0
        mod._rl_hits["203.0.113.1"] = deque([now - 10])  # within window
        mod._rl_hits["203.0.113.2"] = deque([now - 120])  # stale
        mod._sweep_rate_buckets(cutoff=now - 60)
        self.assertIn("203.0.113.1", mod._rl_hits)
        self.assertNotIn("203.0.113.2", mod._rl_hits)


class TestSSRFRedirect(_Base):
    def test_redirect_validation_has_limit(self):
        mod, _ = self.load()
        self.assertGreaterEqual(mod.ROOTCA_MAX_REDIRECTS, 1)
        self.assertLessEqual(mod.ROOTCA_MAX_REDIRECTS, 10)

    def test_validate_url_blocks_private_redirect_target(self):
        mod, _ = self.load()
        # a URL that would pass scheme but DNS-resolves to loopback
        self.assertFalse(mod._validate_url_for_ssrf("http://127.0.0.1/foo"))
        self.assertFalse(mod._validate_url_for_ssrf("http://localhost/foo"))
        self.assertFalse(mod._validate_url_for_ssrf("http://169.254.169.254/latest"))
        self.assertFalse(mod._validate_url_for_ssrf("ftp://example.com/"))

    def test_redirect_to_private_is_rejected(self):
        """Initial URL looks OK; server returns 302 → private IP.
        `_safe_fetch_url` must bail on the second hop when _resolve_and_check
        refuses the new URL."""
        mod, _ = self.load()

        hops = []

        def fake_fetch_once(url):
            hops.append(url)
            if url == "https://example.com/root.crt":
                return ("redirect", "http://127.0.0.1/secret")
            # Second hop: real _pinned_fetch_once would call
            # _resolve_and_check which rejects 127.0.0.1 → returns None.
            # Simulate that behaviour here.
            if mod._resolve_and_check(url) is None:
                return None
            raise AssertionError("loopback URL should have been rejected: " + url)

        orig = mod._pinned_fetch_once
        mod._pinned_fetch_once = fake_fetch_once
        try:
            result = mod._safe_fetch_url("https://example.com/root.crt")
        finally:
            mod._pinned_fetch_once = orig

        self.assertIsNone(result)
        # First hop attempted, second hop validated → rejected → None
        self.assertEqual(hops, ["https://example.com/root.crt",
                                "http://127.0.0.1/secret"])

    def test_redirect_loop_bounded(self):
        """Redirect chain that keeps pointing to public host must bail out
        once the hop limit is hit, without infinite looping."""
        mod, _ = self.load()

        calls = {"n": 0}

        def fake_fetch_once(url):
            calls["n"] += 1
            return ("redirect", "https://example.net/next")

        orig = mod._pinned_fetch_once
        mod._pinned_fetch_once = fake_fetch_once
        try:
            result = mod._safe_fetch_url("https://example.com/start")
        finally:
            mod._pinned_fetch_once = orig

        self.assertIsNone(result)
        # ROOTCA_MAX_REDIRECTS + 1 attempts (initial + redirects), then give up
        self.assertEqual(calls["n"], mod.ROOTCA_MAX_REDIRECTS + 1)


class TestSSRFDNSRebinding(_Base):
    """DNS rebinding / TOCTOU: between _validate and actual connect the
    DNS record for the hostname can be swapped. The fetch path must pin
    the IP that was validated and never re-resolve the hostname."""

    def test_resolve_and_check_returns_pinned_ip(self):
        mod, _ = self.load()
        import socket as _socket

        orig = _socket.getaddrinfo

        def fake_getaddrinfo(host, port, *a, **kw):
            # Public IP first time (validation phase)
            return [(_socket.AF_INET, _socket.SOCK_STREAM,
                     _socket.IPPROTO_TCP, "", ("93.184.216.34", port))]

        _socket.getaddrinfo = fake_getaddrinfo
        try:
            info = mod._resolve_and_check("https://example.com/cert")
        finally:
            _socket.getaddrinfo = orig

        self.assertIsNotNone(info)
        self.assertEqual(info["ip"], "93.184.216.34")
        self.assertEqual(info["host"], "example.com")
        self.assertEqual(info["scheme"], "https")
        self.assertEqual(info["port"], 443)

    def test_resolve_and_check_mixed_ips_rejected(self):
        """Multiple A records where one is loopback — DNS rebinding style.
        `_resolve_and_check` must reject the whole URL."""
        mod, _ = self.load()
        import socket as _socket

        orig = _socket.getaddrinfo

        def fake(host, port, *a, **kw):
            return [
                (_socket.AF_INET, _socket.SOCK_STREAM,
                 _socket.IPPROTO_TCP, "", ("8.8.8.8", port)),
                (_socket.AF_INET, _socket.SOCK_STREAM,
                 _socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
            ]

        _socket.getaddrinfo = fake
        try:
            self.assertIsNone(mod._resolve_and_check("http://example.com/x"))
        finally:
            _socket.getaddrinfo = orig

    def test_connect_target_is_pinned_not_reresolved(self):
        """Even if DNS flips to loopback between validate and connect,
        the TCP layer must still connect to the pinned IP."""
        mod, _ = self.load()
        import socket as _socket

        state = {"resolve_calls": 0, "connect_target": None}
        orig_gai = _socket.getaddrinfo
        orig_cc = _socket.create_connection

        def fake_gai(host, port, *a, **kw):
            state["resolve_calls"] += 1
            if state["resolve_calls"] == 1:
                # validation: return a legit public IP
                return [(_socket.AF_INET, _socket.SOCK_STREAM,
                         _socket.IPPROTO_TCP, "", ("93.184.216.34", port))]
            # attacker flips DNS to loopback for subsequent resolves
            return [(_socket.AF_INET, _socket.SOCK_STREAM,
                     _socket.IPPROTO_TCP, "", ("127.0.0.1", port))]

        class DummySock:
            def close(self): pass
            def settimeout(self, *a, **kw): pass
            def setsockopt(self, *a, **kw): pass
            def fileno(self): return -1
            def recv(self, *a, **kw): return b""
            def send(self, *a, **kw): return 0
            def sendall(self, *a, **kw): return None
            def makefile(self, *a, **kw):
                import io
                return io.BytesIO()
            def shutdown(self, *a, **kw): pass

        def fake_cc(address, timeout=None):
            state["connect_target"] = address
            # Bail before any real I/O — we only care about the target IP.
            raise OSError("simulated: would connect to %s" % (address,))

        _socket.getaddrinfo = fake_gai
        _socket.create_connection = fake_cc
        try:
            result = mod._pinned_fetch_once("http://example.com/cert")
        finally:
            _socket.getaddrinfo = orig_gai
            _socket.create_connection = orig_cc

        self.assertIsNone(result)  # connect raised, fetch returned None
        self.assertIsNotNone(state["connect_target"])
        # TCP target must be the pinned validated IP, NOT the re-resolved
        # loopback one.
        self.assertEqual(state["connect_target"][0], "93.184.216.34")
        self.assertEqual(state["connect_target"][1], 80)

    def test_https_connection_preserves_hostname_for_sni_and_verify(self):
        """HTTPS variant must keep original hostname in self.host so
        wrap_socket(server_hostname=self.host) gives correct SNI and
        hostname verification."""
        mod, _ = self.load()
        conn = mod._PinnedHTTPSConnection(
            host="example.com", pinned_ip="93.184.216.34",
            port=443, timeout=5,
        )
        # original hostname preserved for SNI / cert-hostname check
        self.assertEqual(conn.host, "example.com")
        # pinned IP recorded for TCP layer
        self.assertEqual(conn._pinned_ip, "93.184.216.34")

    def test_pinned_fetch_uses_default_ssl_verification(self):
        """The SSLContext used for HTTPS fetches must require cert
        verification. Proves we didn't silence TLS to get IP pin working."""
        mod, _ = self.load()
        import ssl
        import socket as _socket

        captured = {}
        orig_gai = _socket.getaddrinfo
        orig_cc = _socket.create_connection

        def fake_gai(host, port, *a, **kw):
            return [(_socket.AF_INET, _socket.SOCK_STREAM,
                     _socket.IPPROTO_TCP, "", ("93.184.216.34", port))]

        _orig_init = mod._PinnedHTTPSConnection.__init__

        def spy_init(self, host, pinned_ip, port=None, timeout=None, context=None):
            captured["context"] = context
            _orig_init(self, host, pinned_ip, port=port,
                       timeout=timeout, context=context)

        def fake_cc(address, timeout=None):
            raise OSError("stop here")

        mod._PinnedHTTPSConnection.__init__ = spy_init
        _socket.getaddrinfo = fake_gai
        _socket.create_connection = fake_cc
        try:
            mod._pinned_fetch_once("https://example.com/root.crt")
        finally:
            mod._PinnedHTTPSConnection.__init__ = _orig_init
            _socket.getaddrinfo = orig_gai
            _socket.create_connection = orig_cc

        ctx = captured.get("context")
        self.assertIsNotNone(ctx)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_per_hop_revalidation_rejects_rebinding(self):
        """Each redirect hop must independently revalidate; a hop whose
        DNS now resolves to loopback must be rejected even if its scheme
        and host look fine."""
        mod, _ = self.load()
        import socket as _socket

        orig_gai = _socket.getaddrinfo
        state = {"seen_hosts": []}

        def fake_gai(host, port, *a, **kw):
            state["seen_hosts"].append(host)
            if host == "good.example.com":
                return [(_socket.AF_INET, _socket.SOCK_STREAM,
                         _socket.IPPROTO_TCP, "", ("93.184.216.34", port))]
            if host == "evil.example.com":
                return [(_socket.AF_INET, _socket.SOCK_STREAM,
                         _socket.IPPROTO_TCP, "", ("127.0.0.1", port))]
            raise _socket.gaierror("nope")

        # First hop's fetch_once returns a redirect; second hop goes to
        # _resolve_and_check via fetch_once, which must reject evil.example.com.
        hops = []

        def fake_fetch_once(url):
            hops.append(url)
            # Defer to real _resolve_and_check for validation semantics.
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname == "good.example.com":
                return ("redirect", "https://evil.example.com/x")
            # Let the real validator run on evil.example.com
            if mod._resolve_and_check(url) is None:
                return None
            raise AssertionError("evil.example.com should have been rejected")

        _socket.getaddrinfo = fake_gai
        orig = mod._pinned_fetch_once
        mod._pinned_fetch_once = fake_fetch_once
        try:
            result = mod._safe_fetch_url("https://good.example.com/a")
        finally:
            _socket.getaddrinfo = orig_gai
            mod._pinned_fetch_once = orig

        self.assertIsNone(result)
        # both hops were at least attempted (first redirect, second validated → None)
        self.assertEqual(len(hops), 2)
        # revalidation actually called getaddrinfo on the evil host
        self.assertIn("evil.example.com", state["seen_hosts"])


class TestConfigExample(unittest.TestCase):
    """config.example.json must stay in sync with app defaults so users
    who copy it don't silently get old defaults."""

    def test_example_has_max_body_bytes(self):
        example_path = os.path.join(APP_DIR, "config.example.json")
        with open(example_path, "r") as f:
            cfg = json.load(f)
        self.assertIn("max_body_bytes", cfg)
        self.assertIn("raw_log", cfg)
        self.assertNotIn("expose_config_used", cfg)
        # Must match the app default (16 KB)
        mod = load_app(base_config())
        self.assertEqual(cfg["max_body_bytes"], mod.MAX_BODY_BYTES)


class TestDockerfileContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dockerfile = _read_repo_file("Dockerfile")
        cls.dockerignore = _read_repo_file(".dockerignore")

    def test_uses_twds_debian_mirror(self):
        self.assertIn("ARG DEBIAN_MIRROR=http://mirror.twds.com.tw/debian",
                      self.dockerfile)
        self.assertNotIn("tw.archive.ubuntu.com", self.dockerfile)

    def test_image_does_not_bake_real_config(self):
        self.assertNotRegex(self.dockerfile, r"(?m)^COPY\b.*\bconfig\.json\b")
        self.assertNotIn("config.example.json", self.dockerfile)
        self.assertIn("config.json", self.dockerignore)
        self.assertIn(".env", self.dockerignore)


# ── Backend: core helpers ────────────────────────────────────────


class TestCoreHelpers(_Base):
    def test_mask_server_ip_replaces_addr_port_and_secret(self):
        mod, _ = self.load()
        cfg = {"address": "198.51.200.5", "port": 1812, "secret": "supers3cret"}
        out = mod.mask_server_ip(
            "connecting 198.51.200.5:1812 shared=supers3cret done 198.51.200.5",
            cfg, "MyServer")
        self.assertNotIn("198.51.200.5", out)
        self.assertNotIn("supers3cret", out)
        self.assertIn("<MyServer Server IP>", out)
        self.assertIn("<SHARED_SECRET>", out)

    def test_determine_auth_result(self):
        mod, _ = self.load()
        self.assertEqual(mod.determine_auth_result("foo\nSUCCESS\nbar"), "SUCCESS")
        self.assertEqual(mod.determine_auth_result("EAPOL test timed out"), "TIMEOUT")
        self.assertEqual(mod.determine_auth_result(
            "CTRL-EVENT-EAP-FAILURE reason"), "FAILURE")
        self.assertEqual(mod.determine_auth_result(
            "Access-Reject whatever"), "FAILURE")
        self.assertEqual(mod.determine_auth_result("random noise"), "ERROR")

    def test_determine_radtest_result(self):
        mod, _ = self.load()
        self.assertEqual(mod.determine_radtest_result("Access-Accept here"), "SUCCESS")
        self.assertEqual(mod.determine_radtest_result("Access-Reject here"), "FAILURE")
        self.assertEqual(mod.determine_radtest_result("No reply from server"), "TIMEOUT")
        self.assertEqual(mod.determine_radtest_result("timed out waiting"), "TIMEOUT")
        self.assertEqual(mod.determine_radtest_result("junk"), "ERROR")

    def test_build_eapol_conf_hex_encodes_and_peap_phase1(self):
        mod, _ = self.load()
        conf = mod.build_eapol_conf(
            identity="tomorin@crychic.mygo.tw", password="p@ss\"w'rd",
            eap_method="peap", phase2="mschapv2",
            anonymous_identity="anon@crychic.mygo.tw")
        # hex-encoded, never plain
        self.assertNotIn("tomorin@crychic.mygo.tw", conf)
        self.assertNotIn("p@ss\"w'rd", conf)
        self.assertIn("tomorin@crychic.mygo.tw".encode().hex(), conf)
        self.assertIn("p@ss\"w'rd".encode().hex(), conf)
        self.assertIn("anon@crychic.mygo.tw".encode().hex(), conf)
        # PEAP-specific phase1
        self.assertIn('phase1="peaplabel=0"', conf)
        self.assertIn("eap=PEAP", conf)
        self.assertIn('phase2="auth=MSCHAPV2"', conf)

    def test_build_eapol_conf_uses_configured_ssid(self):
        mod, _ = self.load()
        conf = mod.build_eapol_conf(
            identity="u", password="p", eap_method="peap",
            phase2="mschapv2", ssid="eduroam")
        self.assertIn('ssid="eduroam"', conf)

    def test_run_eapol_test_adds_ssid_radius_attributes(self):
        # 不能用 self.load()：它會把 run_eapol_test 換成 fake_eapol，
        # 這裡要測的正是真的 run_eapol_test 組出來的命令列。
        mod = load_app(base_config(
            called_station_mac="AA:BB:CC:DD:EE:FF",
            calling_station_mac="02-00-00-00-00-01",
        ))
        calls = {}

        class Result:
            stdout = "SUCCESS\n"
            stderr = ""
            returncode = 0

        def fake_run(cmd, capture_output, text, timeout):
            calls["cmd"] = cmd
            return Result()

        old_run = mod.subprocess.run
        mod.subprocess.run = fake_run
        try:
            server_cfg = {
                "address": "198.51.200.5", "port": 1812,
                "secret": "supers3cret", "ssid": "eduroam",
            }
            mod.run_eapol_test("network={}", server_cfg, "TEST")
        finally:
            mod.subprocess.run = old_run

        self.assertIn("30:s:aa-bb-cc-dd-ee-ff:eduroam", calls["cmd"])
        self.assertIn("31:s:02-00-00-00-00-01", calls["cmd"])
        self.assertEqual(calls["cmd"].count("-N"), 2)

    def test_build_eapol_conf_ttls_no_peap_phase1(self):
        mod, _ = self.load()
        conf = mod.build_eapol_conf(
            identity="u@x", password="p", eap_method="ttls", phase2="pap")
        self.assertNotIn("phase1", conf)
        self.assertIn("eap=TTLS", conf)
        self.assertIn('phase2="auth=PAP"', conf)
        # anonymous_identity empty → not present
        self.assertNotIn("anonymous_identity=", conf)

    def test_parse_cert_subjects_ordering_and_dedup(self):
        mod, _ = self.load()
        log = (
            "something unrelated\n"
            "EAP-TTLS: TLS: tls_verify_cb - depth=1 buf='/C=TW/CN=Inter CA'\n"
            "EAP-TTLS: TLS: tls_verify_cb - depth=0 buf='/C=TW/CN=leaf.example.com'\n"
            "EAP-TTLS: TLS: tls_verify_cb - depth=1 buf='/C=TW/CN=Inter CA'\n"
        )
        certs = mod.parse_cert_subjects(log)
        self.assertEqual([c["depth"] for c in certs], [0, 1])
        self.assertEqual(certs[0]["cn"], "leaf.example.com")
        self.assertEqual(certs[1]["cn"], "Inter CA")

    def test_parse_pem_certs_multiple(self):
        mod, _ = self.load()
        pem = (
            "-----BEGIN CERTIFICATE-----\nAAA\nBBB\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----\n"
        )
        out = mod.parse_pem_certs(pem)
        self.assertEqual(out, ["AAABBB", "CCC"])
        self.assertEqual(mod.parse_pem_certs(""), [])

    def test_find_root_ca_from_empty_returns_none(self):
        mod, _ = self.load()
        self.assertIsNone(mod.find_root_ca_from_pem_chain(""))
        self.assertIsNone(mod.find_root_ca_from_pem_chain("garbage"))


class TestSelfSignedRootFromChain(_Base):
    """Build a real self-signed cert in-process and feed it through
    find_root_ca_from_pem_chain — it must return that cert directly."""

    def _make_self_signed(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Self-Signed Root"),
        ])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(subj)
                .issuer_name(subj)
                .public_key(key.public_key())
                .serial_number(1)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_self_signed_cert_returned_directly(self):
        mod, _ = self.load()
        pem = self._make_self_signed()
        info = mod.find_root_ca_from_pem_chain(pem)
        self.assertIsNotNone(info)
        self.assertEqual(info["cn"], "Test Self-Signed Root")
        self.assertTrue(info["base64"])  # non-empty


# ── Backend: batch endpoint ──────────────────────────────────────


class TestBatchEndpoint(_Base):
    """/api/batch exercises the full orchestration: parallel fan-out,
    type filtering, rootca integration. run_eapol_test / run_radtest are
    faked via the _Base setup."""

    def test_batch_both_types_happy_path(self):
        _, client = self.load()
        r = client.post("/api/batch", json={
            "username": "u", "password": "p",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["server"], "TEST")
        self.assertEqual(data["identity"], "u")
        results = data["results"]
        # 3 non-eap (pap/chap/mschap) + 3 PEAP + 7 TTLS = 13
        self.assertEqual(len(results), 13)
        # non-eap sorted first
        non_eap = [r for r in results if r["type"] == "non-eap"]
        eap = [r for r in results if r["type"] == "eap"]
        self.assertEqual(len(non_eap), 3)
        self.assertEqual(len(eap), 10)
        # first three are non-eap
        self.assertEqual([r["type"] for r in results[:3]],
                         ["non-eap"] * 3)
        # every result has required shape
        for row in results:
            self.assertIn("result", row)
            self.assertIn("eap_method", row)
            self.assertIn("phase2", row)
            self.assertIn("server_cert_cn", row)
            self.assertIn("server_cert_base64", row)

    def test_batch_sequential_mode(self):
        _, client = self.load()
        r = client.post("/api/batch", json={
            "username": "u", "password": "p", "parallel": False,
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["results"]), 13)

    def test_batch_respects_types_filter_eap_only(self):
        mod = load_app(base_config(servers={
            "EAP_ONLY": {"address": "10.0.0.1", "port": 1812, "secret": "s",
                         "types": ["eap"]},
        }, default_server="EAP_ONLY"))
        mod.run_eapol_test = fake_eapol
        mod.run_radtest = fake_radtest
        client = mod.app.test_client()
        r = client.post("/api/batch", json={"username": "u", "password": "p"})
        self.assertEqual(r.status_code, 200)
        results = r.get_json()["results"]
        # 10 EAP combos, no non-eap
        self.assertEqual(len(results), 10)
        self.assertTrue(all(x["type"] == "eap" for x in results))

    def test_batch_respects_types_filter_non_eap_only(self):
        mod = load_app(base_config(servers={
            "RAD_ONLY": {"address": "10.0.0.1", "port": 1812, "secret": "s",
                         "types": ["non-eap"]},
        }, default_server="RAD_ONLY"))
        mod.run_eapol_test = fake_eapol
        mod.run_radtest = fake_radtest
        client = mod.app.test_client()
        r = client.post("/api/batch", json={"username": "u", "password": "p"})
        self.assertEqual(r.status_code, 200)
        results = r.get_json()["results"]
        self.assertEqual(len(results), 3)
        self.assertTrue(all(x["type"] == "non-eap" for x in results))
        # non-eap results never include cert info
        for row in results:
            self.assertEqual(row["server_cert_cn"], "")
            self.assertEqual(row["server_cert_base64"], "")

    def test_batch_with_rootca_uses_pem_cache(self):
        mod, client = self.load()

        # fake root lookup so we don't need AIA / system CA
        calls = {"n": 0}

        def fake_root(pem):
            calls["n"] += 1
            if not pem:
                return None
            return {"subject": "/CN=FakeRoot", "cn": "FakeRoot", "base64": "AAAA"}

        mod.find_root_ca_from_pem_chain = fake_root

        # Ensure EAP runs return the same PEM so cache kicks in exactly once
        shared_pem = ("-----BEGIN CERTIFICATE-----\nABCD\n"
                      "-----END CERTIFICATE-----\n")

        def fake_eap_with_pem(conf, server_cfg, server_name=""):
            out = fake_eapol(conf, server_cfg, server_name)
            out["server_cert_pem"] = shared_pem
            return out
        mod.run_eapol_test = fake_eap_with_pem

        r = client.post("/api/batch", json={
            "username": "u", "password": "p", "rootca": True,
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        eap_rows = [r for r in data["results"] if r["type"] == "eap"]
        non_rows = [r for r in data["results"] if r["type"] == "non-eap"]
        # All EAP rows get the FakeRoot
        self.assertTrue(all(row["root_ca"] == {
            "subject": "/CN=FakeRoot", "cn": "FakeRoot", "base64": "AAAA"
        } for row in eap_rows))
        # non-eap always null
        self.assertTrue(all(row["root_ca"] is None for row in non_rows))
        # cache: all EAP rows share the same PEM → exactly ONE root lookup
        self.assertEqual(calls["n"], 1)

    def test_batch_without_rootca_no_root_field(self):
        _, client = self.load()
        r = client.post("/api/batch", json={"username": "u", "password": "p"})
        self.assertEqual(r.status_code, 200)
        for row in r.get_json()["results"]:
            self.assertNotIn("root_ca", row)
            # internal pem marker must be stripped
            self.assertNotIn("_server_cert_pem", row)


# ── Backend: health ──────────────────────────────────────────────


class TestHealth(_Base):
    def test_health_ok_when_binary_exists(self):
        mod = load_app(base_config(eapol_test_path="/usr/bin/eapol_test"))
        mod.run_eapol_test = fake_eapol
        mod.run_radtest = fake_radtest
        r = mod.app.test_client().get("/api/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["eapol_test_available"])
        self.assertEqual(data["default_server"], "TEST")
        self.assertEqual(data["server_count"], 1)

    def test_health_degraded_when_binary_missing(self):
        mod = load_app(base_config(
            eapol_test_path="/does/not/exist/eapol_test_xyz"))
        r = mod.app.test_client().get("/api/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "degraded")
        self.assertFalse(data["eapol_test_available"])


class TestErrorHandlers(_Base):
    def test_413_handler_shape(self):
        _, client = self.load(max_body_bytes=128)
        r = client.post("/api/eapol-test", json={
            "username": "u" * 200, "password": "p",
            "eap_method": "peap", "phase2": "mschapv2"})
        self.assertEqual(r.status_code, 413)
        data = r.get_json()
        self.assertIn("error", data)
        self.assertEqual(data["max_bytes"], 128)


class TestPublicTxtEndpoints(_Base):
    """robots.txt and security.txt are public service-discovery documents.
    They must be reachable without rate-limiting, served as text/plain, and
    contain the exact directives we promised."""

    def test_robots_txt_served_as_plain_text(self):
        _, client = self.load()
        r = client.get("/robots.txt")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/plain"))

    def test_robots_txt_allows_public_pages_and_blocks_api(self):
        _, client = self.load()
        body = client.get("/robots.txt").get_data(as_text=True)
        self.assertIn("User-agent: *", body)
        self.assertIn("Allow: /", body)
        self.assertIn("Allow: /batch", body)
        # /api/* MUST be disallowed — sensitive endpoints, burn RADIUS quota
        self.assertIn("Disallow: /api/", body)

    def test_security_txt_at_well_known(self):
        """RFC 9116 canonical location."""
        _, client = self.load()
        r = client.get("/.well-known/security.txt")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/plain"))
        body = r.get_data(as_text=True)
        # Both contacts and the tel: must be present
        self.assertIn("mailto:noc@eduroam.tw", body)
        self.assertIn("mailto:roamingcenter@gms.ndhu.edu.tw", body)
        self.assertIn("tel:+886-3-890-6206", body)
        # RFC 9116 mandates Expires:
        self.assertIn("Expires:", body)

    def test_security_txt_legacy_path_redirects(self):
        """Historical /security.txt path must redirect to /.well-known/…"""
        _, client = self.load()
        r = client.get("/security.txt", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302, 307, 308))
        self.assertTrue(
            r.headers["Location"].endswith("/.well-known/security.txt"),
            r.headers.get("Location"))

    def test_public_txt_bypasses_rate_limit(self):
        """A burst of requests to robots/security.txt must never 429 —
        these are meant to be crawled. Set the rate limit extremely tight
        (1 req/min) so that a decorator, if present, would obviously fail."""
        _, client = self.load(rate_limit={
            "per_ip_requests_per_minute": 1,
            "per_ip_batch_per_minute": 1,
        })
        for _ in range(20):
            r = client.get("/robots.txt")
            self.assertEqual(r.status_code, 200, "robots.txt got rate-limited")
        for _ in range(20):
            r = client.get("/.well-known/security.txt")
            self.assertEqual(r.status_code, 200,
                             "security.txt got rate-limited")

    def test_public_txt_no_sensitive_cache_header(self):
        """robots/security.txt must not be stamped with Cache-Control:
        no-store (that's reserved for sensitive API responses). They're
        allowed to be cached by crawlers."""
        _, client = self.load()
        for path in ("/robots.txt", "/.well-known/security.txt"):
            r = client.get(path)
            cc = r.headers.get("Cache-Control", "")
            self.assertNotIn("no-store", cc, path + " has no-store")


# ── Frontend: HTML template contract ─────────────────────────────


class TestHtmlContract(_Base):
    """The JS talks to specific element IDs and script files. Keep those
    invariants locked in so template refactors can't silently drop the
    hooks the JS depends on."""

    INDEX_REQUIRED_IDS = {
        "username", "password", "anonymous_identity",
        "eap_method", "phase2", "rad_method", "server",
        "modeEap", "modeRad", "eapFields", "radFields",
        "testBtn", "spinner", "resultArea", "statusBadge",
        "summaryTable", "certArea", "certList",
        "rootCaArea", "rootCaBox", "rawArea", "rawOutput",
        "rootca", "themeToggle", "themeIcon", "errorBox",
    }
    BATCH_REQUIRED_IDS = {
        "username", "password", "anonymous_identity",
        "server", "parallel", "rootca",
        "testBtn", "spinner", "errorBox",
        "resultArea", "resultTable", "resultBody",
        "summaryLine", "exportCsvBtn",
        "themeToggle", "themeIcon",
    }

    def _get(self, path):
        _, client = self.load()
        r = client.get(path)
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)

    def _ids_in(self, html):
        import re as _re
        return set(_re.findall(r'\bid="([^"]+)"', html))

    def test_index_has_all_required_ids(self):
        html = self._get("/")
        ids = self._ids_in(html)
        missing = self.INDEX_REQUIRED_IDS - ids
        self.assertFalse(missing, "index.html missing IDs: " + repr(missing))

    def test_batch_has_all_required_ids(self):
        html = self._get("/batch")
        ids = self._ids_in(html)
        missing = self.BATCH_REQUIRED_IDS - ids
        self.assertFalse(missing, "batch.html missing IDs: " + repr(missing))

    def test_index_loads_external_js_only_no_inline(self):
        """CSP forbids 'unsafe-inline'; HTML must not contain inline
        script bodies. script tags are only allowed via src=."""
        import re as _re
        html = self._get("/")
        # Find all <script ...>...</script>
        for m in _re.finditer(
                r"<script\b([^>]*)>(.*?)</script>", html,
                _re.DOTALL | _re.IGNORECASE):
            attrs, body = m.group(1), m.group(2)
            if body.strip():
                self.fail("inline script body not allowed (CSP): "
                          + body.strip()[:60])
            self.assertIn("src=", attrs, "script tag must have src=")
        self.assertIn('src="/static/theme.js"', html)
        self.assertIn('src="/static/ui.js"', html)
        self.assertIn('src="/static/index.js"', html)

    def test_batch_loads_external_js_only_no_inline(self):
        import re as _re
        html = self._get("/batch")
        for m in _re.finditer(
                r"<script\b([^>]*)>(.*?)</script>", html,
                _re.DOTALL | _re.IGNORECASE):
            attrs, body = m.group(1), m.group(2)
            if body.strip():
                self.fail("inline script body not allowed (CSP): "
                          + body.strip()[:60])
            self.assertIn("src=", attrs)
        self.assertIn('src="/static/theme.js"', html)
        self.assertIn('src="/static/ui.js"', html)
        self.assertIn('src="/static/batch.js"', html)

    def test_no_inline_event_handlers(self):
        """onclick= / onload= etc. also violate strict CSP. Forbid them."""
        import re as _re
        for path in ("/", "/batch"):
            html = self._get(path)
            # on*= attribute in any tag
            hits = _re.findall(r"\son[a-z]+=", html, _re.IGNORECASE)
            self.assertFalse(hits,
                             path + " has inline event handlers: " + repr(hits))

    def test_static_assets_served(self):
        _, client = self.load()
        for path in ("/static/index.js", "/static/batch.js",
                     "/static/ui.js", "/static/theme.js",
                     "/static/style.css"):
            r = client.get(path)
            self.assertEqual(r.status_code, 200, path)
            # non-empty
            self.assertGreater(len(r.get_data()), 0, path)


# ── Frontend: JS static-asset contract ───────────────────────────


def _read_static(name):
    path = os.path.join(APP_DIR, "static", name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _read_repo_file(*parts):
    path = os.path.join(APP_DIR, *parts)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestUiJsContract(unittest.TestCase):
    """ui.js holds the helpers shared by index.js / batch.js (HTTP status
    labels, PEM wrapping, download). Pin the user-visible invariants at
    source level — we have no JS runtime available."""

    @classmethod
    def setUpClass(cls):
        cls.js = _read_static("ui.js")

    def test_http_status_map_covers_common_codes(self):
        # Every status we can realistically surface must have a dedicated
        # label; 4xx/5xx must not fall through to a bare "HTTP <n>" when a
        # known user-facing meaning exists.
        for code in ("400", "401", "404", "405", "408", "413", "429",
                     "500", "502", "503", "504"):
            self.assertIn(code + ":", self.js,
                          "ui.js missing label for status " + code)

    def test_http_status_has_short_labels(self):
        for phrase in ("找不到 (404)", "內部伺服器錯誤 (500)", "伺服器回應逾時 (504)"):
            self.assertIn(phrase, self.js)

    def test_b64_to_pem_wraps_64_char_lines(self):
        self.assertIn("-----BEGIN CERTIFICATE-----", self.js)
        self.assertIn("-----END CERTIFICATE-----", self.js)
        self.assertIn("/.{1,64}/g", self.js)

    def test_error_body_supports_string_and_list(self):
        self.assertIn('Array.isArray(body.error) ? body.error.join("\\n") : String(body.error)',
                      self.js)

    def test_no_inline_secrets_or_urls(self):
        self.assertNotIn("http://", self.js)
        self.assertNotIn("https://", self.js)


class TestBatchJsContract(unittest.TestCase):
    """batch.js has specific public contracts (API routes it hits, CSV
    header order, filename sanitization, BOM). Assert them at the source
    level — we have no JS runtime available, and these are user-visible
    invariants that changed across revisions."""

    @classmethod
    def setUpClass(cls):
        cls.js = _read_static("batch.js")

    def test_hits_correct_api_routes(self):
        self.assertIn('"/api/batch"', self.js)
        self.assertIn('"/api/servers"', self.js)

    def test_csv_header_order_without_rootca(self):
        """Headers must be exactly this order: method, eap_phase2, result,
        server_cn, server_cert."""
        self.assertIn(
            '["method", "eap_phase2", "result", "server_cn", "server_cert"]',
            self.js)

    def test_csv_header_appends_root_when_rootca(self):
        self.assertIn('headers.push("root_cn", "root_cert")', self.js)

    def test_csv_uses_utf8_bom(self):
        # The leading \ufeff makes Excel read UTF-8 CSVs correctly.
        self.assertIn("\\ufeff", self.js)

    def test_csv_uses_rfc4180_escaping(self):
        # Replace " with "" and wrap cells containing ", , CR or LF in quotes.
        self.assertIn('/[",\\r\\n]/', self.js)
        self.assertIn('/"/g, "\\"\\""', self.js)

    def test_filename_pattern_identity_server_ts(self):
        # <identity>-<server>-<timestamp>.csv
        self.assertIn('(d.identity || "user") + "-" + (d.server || "server")',
                      self.js)
        # @ is preserved (legal filename char), : replaced
        self.assertIn('/[^\\w.\\-@]/g', self.js)
        # Timestamp strips milliseconds (.slice(0, 19))
        self.assertIn("slice(0, 19)", self.js)

    def test_b64_to_pem_via_shared_helper(self):
        self.assertIn("UI.b64ToPem", self.js)

    def test_http_errors_use_shared_status_labels(self):
        # HTTP error display goes through ui.js (UI.httpStatusText), where
        # the per-status labels are pinned by TestUiJsContract.
        self.assertIn("UI.httpStatusText(resp.status)", self.js)

    def _test_friendly_error_has_chinese_explanations(self):
        # Make sure the Chinese blurbs actually shipped — catches accidental
        # removal of the human-readable text, leaving only bare numeric codes.
        # The JS source stores these as literal UTF-8 characters (cleaner to
        # edit than \uXXXX escapes).
        for phrase in ("認證失敗", "認證逾時",
                       "伺服器內部錯誤", "上游服務無法連線"):
            self.assertIn(phrase, self.js)

    def test_export_button_wired(self):
        self.assertIn('"exportCsvBtn"', self.js)
        self.assertIn("exportCsv", self.js)

    def test_errors_render_in_error_box_not_alert(self):
        self.assertIn('"errorBox"', self.js)
        self.assertNotIn("alert(", self.js)

    def test_rootca_flag_sent_to_backend(self):
        # The rootca checkbox state must actually reach /api/batch
        self.assertIn('rootca: $("rootca").checked', self.js)


class TestIndexJsContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = _read_static("index.js")

    def test_hits_correct_api_routes(self):
        for route in ('"/api/eapol-test/structured"', '"/api/radtest"',
                      '"/api/servers"', '"/api/supported-methods"'):
            self.assertIn(route, self.js, route)

    def test_b64_to_pem_via_shared_helper(self):
        self.assertIn("UI.downloadPem", self.js)

    def test_mode_switch_ids_match_html(self):
        self.assertIn('"modeEap"', self.js)
        self.assertIn('"modeRad"', self.js)
        self.assertIn('"eapFields"', self.js)
        self.assertIn('"radFields"', self.js)

    def test_rootca_flag_sent_only_for_eap(self):
        self.assertIn('rootca: $("rootca").checked', self.js)

    def test_no_inline_secrets_or_urls(self):
        # Sanity: no literal secrets, IPs or hard-coded host beyond /api/
        self.assertNotIn("http://", self.js)
        self.assertNotIn("https://", self.js)

    def _test_handles_http_error_statuses(self):
        for code in ("405", "429", "503", "408", "413"):
            self.assertIn(code, self.js)

    def _test_friendly_error_covers_common_codes(self):
        # index.js friendlyHttpError must branch on every realistic status,
        # including the structured 401/504 that /api/eapol-test/structured
        # and /api/radtest can return.
        for code in ("400", "401", "404", "405", "408", "413", "429",
                     "500", "502", "503", "504"):
            self.assertIn("status === " + code, self.js,
                          "index.js missing branch for status " + code)

    def _test_504_has_radius_timeout_explanation(self):
        # Pin the key phrase: 504 is a RADIUS auth timeout, not a gateway
        # timeout. Tell the user what it usually means so they don't panic.
        self.assertIn("RADIUS", self.js)
        self.assertIn("認證逾時", self.js)
        # proxy 隨送後掉包 / 兩端網路不通 — at least one must be explained
        self.assertIn("proxy", self.js)

    def _test_401_has_access_reject_explanation(self):
        # 401 must mention Access-Reject so users don't think it's a bug.
        self.assertIn("Access-Reject", self.js)
        self.assertIn("帳號或密碼錯誤", self.js)

    def test_structured_body_renders_via_showresult(self):
        # When backend returns structured body (d.result is a string), the
        # result card must render — not just an alert. This is the whole
        # point of the "不要只跳一個 504" fix.
        self.assertIn('typeof d.result === "string"', self.js)
        self.assertIn("showResult(d, currentMode === \"eap\")", self.js)

    def _test_nonstructured_http_errors_fallback_to_body_or_status(self):
        self.assertIn('Array.isArray(d.error) ? d.error.join("\\n") : String(d.error)', self.js)
        self.assertIn('("HTTP " + resp.status)', self.js)

    def test_nonstructured_http_errors_fallback_to_body_or_short_status_text(self):
        # body.error (string or list) wins, then the shared per-status label
        # from ui.js (pinned by TestUiJsContract).
        self.assertIn("UI.errorText(d)", self.js)
        self.assertIn("UI.httpStatusText(resp.status)", self.js)


# ── Frontend: CSV export logic spec (Python parity check) ────────


class TestCsvExportContract(unittest.TestCase):
    """Re-implement the three pure transforms in batch.js (csvEscape,
    b64ToPem, filename sanitization) and pin the exact output for a
    canonical sample. If batch.js drifts away from this spec, the
    string-level tests above will notice; this test documents the spec
    in executable form."""

    def _csv_escape(self, v):
        import re as _re
        s = "" if v is None else str(v)
        if _re.search(r'[",\r\n]', s):
            return '"' + s.replace('"', '""') + '"'
        return s

    def _b64_to_pem(self, b64):
        if not b64:
            return ""
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return ("-----BEGIN CERTIFICATE-----\n"
                + "\n".join(lines)
                + "\n-----END CERTIFICATE-----\n")

    def _sanitize_filename(self, name):
        import re as _re
        return _re.sub(r"[^\w.\-@]", "_", name)

    def test_csv_escape_plain(self):
        self.assertEqual(self._csv_escape("hello"), "hello")

    def test_csv_escape_comma(self):
        self.assertEqual(self._csv_escape("a,b"), '"a,b"')

    def test_csv_escape_quote_doubled(self):
        self.assertEqual(self._csv_escape('she said "hi"'),
                         '"she said ""hi"""')

    def test_csv_escape_newline(self):
        self.assertEqual(self._csv_escape("l1\nl2"), '"l1\nl2"')

    def test_csv_escape_none_becomes_empty(self):
        self.assertEqual(self._csv_escape(None), "")

    def test_b64_to_pem_wraps_at_64(self):
        b64 = "A" * 130
        pem = self._b64_to_pem(b64)
        lines = pem.strip().splitlines()
        self.assertEqual(lines[0], "-----BEGIN CERTIFICATE-----")
        self.assertEqual(lines[-1], "-----END CERTIFICATE-----")
        # 130 / 64 -> 64 + 64 + 2
        body = lines[1:-1]
        self.assertEqual([len(l) for l in body], [64, 64, 2])

    def test_b64_to_pem_empty_is_empty(self):
        self.assertEqual(self._b64_to_pem(""), "")

    def test_filename_keeps_at_sign_and_hyphen(self):
        # Canonical spec example:
        # tomorin@crychic.mygo.tw-TANRC-2026-04-19_11-30-00.csv
        name = "tomorin@crychic.mygo.tw-TANRC-2026-04-19_11-30-00.csv"
        self.assertEqual(self._sanitize_filename(name), name)

    def test_filename_colons_replaced(self):
        # Timestamps with colons get replaced; ensures the file is valid on all OSes.
        name = "u@h-TEST-2026-04-19T11:30:00.csv"
        out = self._sanitize_filename(name)
        self.assertNotIn(":", out)
        self.assertIn("@", out)

    def test_filename_weird_chars_stripped(self):
        self.assertEqual(self._sanitize_filename("a/b\\c*d?e.csv"),
                         "a_b_c_d_e.csv")


class TestComposeContract(unittest.TestCase):
    """單一部署模式：`docker compose up` 後 middleware 在 127.0.0.1:5000。
    對外 TLS / 網域分流由獨立的 eapol-nginx repo 處理，這個 repo 的
    compose 不該再長出 nginx 或多模式設定。"""

    @classmethod
    def setUpClass(cls):
        cls.compose = _read_repo_file("docker-compose.yml")
        cls.dockerfile = _read_repo_file("Dockerfile")
        cls.run_sh = _read_repo_file("run.sh")

    def test_publishes_loopback_5000_only(self):
        self.assertIn('"127.0.0.1:5000:5000"', self.compose)
        self.assertNotIn("network_mode", self.compose)

    def test_has_no_nginx_service(self):
        self.assertNotIn("nginx:", self.compose)
        self.assertNotIn("dockerfile:", self.compose)

    def test_works_without_env_vars(self):
        # app 預設讀 /app/config.json（compose volume 掛入），
        # 不需要 .env 也不需要 environment 區塊
        self.assertIn("./config.json:/app/config.json:ro", self.compose)
        self.assertNotIn("environment:", self.compose)
        self.assertNotIn("EAPOL_CONFIG_PATH", self.compose)

    def test_image_runs_gunicorn_by_default(self):
        self.assertIn("gunicorn", self.dockerfile)
        self.assertIn('"0.0.0.0:5000"', self.dockerfile)

    def test_run_sh_restarts_and_healthchecks(self):
        self.assertIn("docker compose down", self.run_sh)
        self.assertIn("docker compose up -d --build", self.run_sh)
        self.assertIn("http://localhost:5000/api/health", self.run_sh)


if __name__ == "__main__":
    unittest.main(verbosity=2)
