# eapol_test Middleware API 使用文件

802.1X EAP 及傳統 RADIUS 認證測試 HTTP API。

- Base URL：`http://<host>:5000`
- 敏感端點僅接受 **POST**（JSON body 或 form data）；GET 會回 `405 Method Not Allowed`
- 預設 server 由 `config.json` 的 `default_server` 決定，可用 `server` 參數覆寫
- 輸出自動遮蔽 server IP 與 shared secret

---

## 快速開始

```bash
# 健康檢查
curl http://localhost:5000/api/health

# 列出可用 server
curl http://localhost:5000/api/servers

# EAP 測試（PEAP + MSCHAPv2）
curl -X POST http://localhost:5000/api/eapol-test \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"pass","eap_method":"peap","phase2":"mschapv2"}'

# 加 Root CA 追溯
curl -X POST http://localhost:5000/api/eapol-test/structured \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"pass","eap_method":"peap","phase2":"mschapv2","rootca":true}'

# 批次測試所有方法（加 Root CA）
curl -X POST http://localhost:5000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"pass","server":"TANRC","rootca":true}'
```

---

## 參數傳遞

敏感端點一律使用 **POST**：JSON body（建議）或 form POST。不再接受透過 query string 帶入帳密。

### JSON body（建議）

```bash
curl -X POST http://localhost:5000/api/eapol-test \
  -H "Content-Type: application/json" \
  -d '{"username":"u","password":"p","eap_method":"peap","phase2":"mschapv2"}'
```

### Form POST

```bash
curl -X POST http://localhost:5000/api/eapol-test \
  -d "username=u" -d "password=p" -d "eap_method=peap" -d "phase2=mschapv2"
```

---

## 端點列表

| Method | Path                         | 說明                                      |
| ------ | ---------------------------- | ----------------------------------------- |
| GET    | `/api/health`                | 健康檢查                                  |
| GET    | `/api/servers`               | 列出可用 RADIUS server                    |
| GET    | `/api/supported-methods`     | 列出支援的 EAP 方法及 Phase 2             |
| POST   | `/api/eapol-test`            | 802.1X EAP 測試（原始輸出）               |
| POST   | `/api/eapol-test/structured` | 802.1X EAP 測試（結構化 JSON）            |
| POST   | `/api/radtest`               | 傳統 RADIUS 測試（PAP/CHAP/MSCHAP）       |
| POST   | `/api/batch`                 | 批次跑所有方法組合                        |
| GET    | `/`                          | 單一測試前端頁面                          |
| GET    | `/batch`                     | 批次測試前端頁面                          |

對敏感端點發 GET 會收到 `405 Method Not Allowed`。

---

## Root CA 追溯

下列端點接受 `rootca` 參數（bool，預設 `false`）：

- `/api/eapol-test`
- `/api/eapol-test/structured`
- `/api/batch`

`/api/radtest` **不**支援（傳統 RADIUS 無 TLS 交握、無伺服器憑證）。

### 運作規則

1. 若伺服器送來的憑證鏈內已包含自簽憑證（issuer == subject），直接回傳
2. 否則從鏈中最高 intermediate 開始，沿 AIA CA Issuers URL 向上 fetch
3. AIA 缺失時，以 `/etc/ssl/certs/ca-certificates.crt`（Debian 系統信任庫）比對 issuer DN
4. 最高深度 8 層（防迴圈），fetch timeout 由 `rootca_fetch.timeout` 控制（預設 5 秒）、下載大小上限由 `rootca_fetch.max_size_bytes` 控制（預設 256 KB）
5. **SSRF 保護**：僅允許 `http` / `https`，拒絕 `localhost` / `127.0.0.0/8` / `::1` / RFC1918 / link-local / carrier-grade NAT / 常見雲端 metadata 位址；主機名先經 `getaddrinfo` 解析，若解析到封鎖範圍也會拒絕。**HTTP redirect 不自動跟，每一跳的新 URL 會重新跑完整 scheme / host / DNS / IP 驗證，上限 5 次。**
6. **IP pinning（DNS rebinding / TOCTOU 防護）**：每一跳驗證通過後，同一個 `getaddrinfo` 結果會被鎖定，實際 TCP 連線以 `socket.create_connection((pinned_ip, port))` 只連到這個 IP，不再讓底層做第二次 DNS 解析；validate 與 connect 之間 DNS 記錄被換掉也不會繞過封鎖清單。HTTPS 仍使用原始 hostname 做 SNI 與憑證驗證（`ssl.create_default_context()`，`CERT_REQUIRED` + `check_hostname=True`），不會因為 pin IP 而關掉 TLS 驗證。
7. 失敗或無憑證時回傳 `null`（不會拋錯，也不會外洩內部錯誤細節）

---

## GET `/api/health`

檢查中介層狀態。

**回應**

```json
{
  "status": "ok",
  "eapol_test_available": true,
  "server_count": 4,
  "default_server": "TANRC"
}
```

`status`：`ok`（`eapol_test` 執行檔存在）或 `degraded`。

---

## GET `/api/servers`

列出所有可用 RADIUS server（名稱、描述、支援類型；**不含 IP 和 secret**）。

**回應**

```json
{
  "servers": {
    "TANRC": {
      "description": "臺灣學術網路漫遊中心",
      "types": ["eap", "non-eap"]
    },
    "GEANT": {
      "description": "歐盟 eduroam Managed SP",
      "types": ["eap"]
    }
  },
  "default": "TANRC"
}
```

`types` 可包含 `eap`（802.1X）、`non-eap`（傳統 RADIUS）。

---

## GET `/api/supported-methods`

列出支援的 EAP 方法及各自的 Phase 2 選項。

**回應**

```json
{
  "methods": {
    "peap": {
      "phase2_options": ["gtc", "md5", "mschapv2"],
      "default_phase2": "mschapv2"
    },
    "ttls": {
      "phase2_options": ["chap", "eap-gtc", "eap-md5", "eap-mschapv2", "mschap", "mschapv2", "pap"],
      "default_phase2": "pap"
    }
  }
}
```

---

## POST `/api/eapol-test`

執行 802.1X EAP 測試，回傳 **原始** `eapol_test` 輸出。

### 參數

| 參數                 | 必填 | 說明                                              |
| -------------------- | ---- | ------------------------------------------------- |
| `username`           | ✅   | 外層身分（通常是 `user@realm`）                   |
| `password`           | ✅   | 使用者密碼                                        |
| `eap_method`         | ✅   | `peap` 或 `ttls`                                  |
| `phase2`             | ⚪   | 未填則用預設（peap→mschapv2, ttls→pap）           |
| `server`             | ⚪   | server 名稱，未填用 `default_server`              |
| `anonymous_identity` | ⚪   | 匿名外層身分（例如 `anonymous@realm`）            |
| `rootca`             | ⚪   | 是否追溯 Root CA（bool，預設 false）              |

### Phase 2 選項

- **peap**：`mschapv2` / `gtc` / `md5`
- **ttls**：`pap` / `chap` / `mschap` / `mschapv2` / `eap-md5` / `eap-gtc` / `eap-mschapv2`

### 範例

```bash
curl -X POST http://localhost:5000/api/eapol-test \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"pass","eap_method":"peap","phase2":"mschapv2","server":"TANRC","rootca":true}'
```

### 回應

```json
{
  "success": true,
  "return_code": 0,
  "output": "...原始 eapol_test 輸出（IP/secret 已遮蔽）...",
  "server_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "server": "TANRC",
  "root_ca": {
    "subject": "/countryName=TW/organizationName=TAIWAN-CA/.../commonName=TWCA Root Certification Authority",
    "cn": "TWCA Root Certification Authority",
    "base64": "MII..."
  }
}
```

- `root_ca` 欄位：只在 `rootca=true` 時出現；追溯失敗時為 `null`。
- `config_used` 欄位：**預設不回傳**。僅在 `config.json` 的 `raw_log` 設為 `true` 時才會附上 `eapol_test` 的原始 conf（含 ssid、identity 等）。此為除錯用途，公開環境不建議啟用。

### HTTP 狀態碼

| 狀態碼 | 意義                                   |
| ------ | -------------------------------------- |
| 200    | 認證成功（`SUCCESS`）                  |
| 400    | 參數錯誤 / server 不支援 EAP           |
| 401    | 認證失敗                               |
| 405    | 方法不允許（非 POST）                  |
| 413    | Request body 超過 `max_body_bytes`     |
| 429    | Per-IP 請求頻率超限                    |
| 503    | 全域 subprocess / batch 資源忙碌       |

---

## POST `/api/eapol-test/structured`

同 `/api/eapol-test`，但回傳 **結構化 JSON**（含解析後的憑證鏈、Base64 憑證、Root CA）。

### 參數

與 `/api/eapol-test` 相同。

### 範例

```bash
curl -X POST http://localhost:5000/api/eapol-test/structured \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "pass",
    "eap_method": "ttls",
    "phase2": "pap",
    "server": "TANRC",
    "anonymous_identity": "anonymous@example.com",
    "rootca": true
  }'
```

### 回應

```json
{
  "server": "TANRC",
  "identity": "user@example.com",
  "anonymous_identity": "anonymous@example.com",
  "eap_method": "ttls",
  "phase2": "pap",
  "result": "SUCCESS",
  "server_certs": [
    {"depth": 0, "subject": "/C=TW/.../CN=*.example.com", "cn": "*.example.com"},
    {"depth": 1, "subject": "/C=TW/.../CN=Intermediate CA", "cn": "Intermediate CA"}
  ],
  "server_certs_base64": [
    "MII...",
    "MII..."
  ],
  "server_cert_chain": [
    {"subject": "/C=TW/.../CN=*.example.com", "cn": "*.example.com", "base64": "MII..."},
    {"subject": "/C=TW/.../CN=Intermediate CA", "cn": "Intermediate CA", "base64": "MII..."}
  ],
  "root_ca": {
    "subject": "/C=TW/.../CN=TWCA Root Certification Authority",
    "cn": "TWCA Root Certification Authority",
    "base64": "MII..."
  },
  "raw_output": "...原始輸出..."
}
```

`config_used` 同上，僅在 `raw_log=true` 時出現。前端不應假設此欄位一定存在。

### 欄位說明

| 欄位                   | 說明                                                                |
| ---------------------- | ------------------------------------------------------------------- |
| `server_certs`         | 由 eapol_test 詳細 log 解析的 subject（不含 base64）                 |
| `server_certs_base64`  | 原始 PEM chain 的每張 base64（order 依 eapol_test 輸出）             |
| `server_cert_chain`    | 用 `cryptography` 重新排序為 **leaf → root**、依指紋去重，每張含 base64 |
| `root_ca`              | 僅 `rootca=true` 時出現；追溯不到則為 `null`                         |
| `config_used`          | 僅 `raw_log=true` 時出現；除錯用                                     |

### `result` 欄位

| 值        | 意義                             |
| --------- | -------------------------------- |
| `SUCCESS` | 認證成功                         |
| `FAILURE` | EAP-Failure / Access-Reject      |
| `TIMEOUT` | `eapol_test` 逾時                |
| `ERROR`   | 其他錯誤                         |

### HTTP 狀態碼

| 狀態碼 | 意義                           |
| ------ | ------------------------------ |
| 200    | SUCCESS                        |
| 401    | FAILURE / ERROR                |
| 504    | TIMEOUT                        |
| 400    | 參數錯誤                       |
| 405    | 方法不允許                     |
| 413    | Body 超過 `max_body_bytes`     |
| 429    | Per-IP 請求頻率超限            |
| 503    | 資源忙碌                       |

---

## POST `/api/radtest`

執行傳統 RADIUS 測試（透過 `radtest`）。**無 TLS，不支援 `rootca`。**

### 參數

| 參數       | 必填 | 說明                           |
| ---------- | ---- | ------------------------------ |
| `username` | ✅   | 使用者名稱                     |
| `password` | ✅   | 密碼                           |
| `method`   | ✅   | `pap` / `chap` / `mschap`      |
| `server`   | ⚪   | server 名稱                    |

### 範例

```bash
curl -X POST http://localhost:5000/api/radtest \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass","method":"pap","server":"TANRC"}'
```

### 回應

```json
{
  "server": "TANRC",
  "identity": "user",
  "method": "pap",
  "result": "SUCCESS",
  "raw_output": "...radtest 原始輸出..."
}
```

### HTTP 狀態碼

同 `/api/eapol-test/structured`（200 / 401 / 504 / 400 / 405 / 429 / 503）。

### 限制

只有 `types` 包含 `non-eap` 的 server 才能使用，否則回 400。

---

## POST `/api/batch`

批次跑 **所有** EAP 方法組合 + 傳統 RADIUS 方法（依 server 支援類型自動篩選）。

### 參數

| 參數                 | 必填 | 說明                                              |
| -------------------- | ---- | ------------------------------------------------- |
| `username`           | ✅   | 使用者名稱                                        |
| `password`           | ✅   | 密碼                                              |
| `server`             | ⚪   | server 名稱                                       |
| `anonymous_identity` | ⚪   | 匿名外層身分（僅 EAP 使用）                       |
| `parallel`           | ⚪   | 是否平行執行，預設 `true`                         |
| `rootca`             | ⚪   | 是否追溯 Root CA（bool，預設 false）              |

### 範例

```bash
curl -X POST http://localhost:5000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"pass","server":"TANRC","rootca":true}'
```

### 回應

```json
{
  "server": "TANRC",
  "identity": "user@example.com",
  "results": [
    {
      "type": "non-eap",
      "eap_method": "non-eap",
      "phase2": "pap",
      "result": "SUCCESS",
      "server_cert_cn": "",
      "server_cert_base64": "",
      "root_ca": null
    },
    {
      "type": "eap",
      "eap_method": "peap",
      "phase2": "mschapv2",
      "result": "SUCCESS",
      "server_cert_cn": "*.example.com",
      "server_cert_base64": "MII...",
      "root_ca": {
        "subject": "/C=TW/.../CN=TWCA Root Certification Authority",
        "cn": "TWCA Root Certification Authority",
        "base64": "MII..."
      }
    }
  ]
}
```

### 說明

- 每個 EAP 方法 **各自一張 `root_ca`**（concept 上各方法分別做 TLS、各自收到憑證）
- 非 EAP 結果的 `root_ca` 永遠是 `null`
- 失敗或無憑證時 `root_ca` 為 `null`（不會拋錯）
- 同一條憑證鏈在本次 batch 中只走一次 AIA/信任庫查詢（用 PEM 字串做 cache key），同 server 不同方法拿到相同結果時不會重複網路 fetch
- Thread pool worker 上限由 `batch_max_workers` 限制（預設 10），不會無上限開 subprocess

結果排序：先 `non-eap`，再 `eap`；各類型內依 `eap_method`、`phase2` 字典序。

### 測試組合總數

- EAP：3 (PEAP phase2) + 7 (TTLS phase2) = **10**
- non-EAP：**3**（PAP / CHAP / MSCHAP）
- 最多 **13** 組（視 server `types` 支援而定）

### HTTP 狀態碼

| 狀態碼 | 意義                                                 |
| ------ | ---------------------------------------------------- |
| 200    | 成功（個別項目結果在 `results` 陣列內）              |
| 400    | 參數錯誤                                             |
| 405    | 方法不允許                                           |
| 413    | Body 超過 `max_body_bytes`                           |
| 429    | Per-IP batch 頻率超限                                |
| 503    | 全域 batch queue 已滿（有 `Retry-After` header）     |

---

## Rate Limit 與資源保護

所有限制邏輯在 Flask / app 層實作，不依賴 nginx。

### Per-IP Rate Limit

| 端點                               | 預設限制              |
| ---------------------------------- | --------------------- |
| `/api/eapol-test`                  | 30 req/min/IP         |
| `/api/eapol-test/structured`       | 30 req/min/IP         |
| `/api/radtest`                     | 30 req/min/IP         |
| `/api/batch`                       | 3 req/min/IP          |

超出限制時回 `429 Too Many Requests`，並附上 `Retry-After` header（秒）。

### 白名單

`rate_limit.whitelist_ips` 內的 IP 可繞過上述 **per-IP 限制**，支援單一 IP 或 CIDR。預設僅包含 `127.0.0.1/32` 與 `::1/128`。

**注意**：白名單只能跳過 per-IP 限制，**不**能跳過下列全域保護。

Rate limit 用到的 in-memory bucket 會在後續請求進來時伺機清理（至少間隔 60 秒掃一次），把過期且空的 IP 鍵整個拿掉，避免大量不同 IP 讓 dict 無限制成長。

### 全域資源保護

| 限制                          | 預設值   | 超出行為                                  |
| ----------------------------- | -------- | ----------------------------------------- |
| `global_max_subprocesses`     | 50       | 個別測試回 `503 service busy`             |
| `global_max_batch_jobs`       | 5        | 整個 batch 請求回 `503 batch queue full`  |
| `batch_max_workers`           | 10       | 限制單一 batch 內的 thread pool 大小      |
| `max_body_bytes`              | 16384    | 超過回 `413 Request Entity Too Large`      |

### 反向代理下的來源 IP

若部署於 nginx / 其他反向代理後方，將 `config.json` 的 `trust_proxy` 設為 `true`，app 會優先解析 `CF-Connecting-IP`，其次 `X-Forwarded-For` / `X-Real-IP` 取得真實來源 IP；`ProxyFix` 只處理 scheme / host，不再改寫 rate limit 用的 client IP。**未設為 `true` 時不會信任這些 header**。

---

## 安全 Headers

所有 HTML 回應附上：

- `Content-Security-Policy` （無 `'unsafe-inline'`；僅允許 self + Google Fonts）
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store`

敏感 API 回應亦附 `Cache-Control: no-store`。

---

## 錯誤格式

所有 400 錯誤回傳：

```json
{
  "error": [
    "missing required parameter: username",
    "unsupported EAP method: xyz, available: peap, ttls"
  ]
}
```

`error` 可能為字串或字串陣列。429 / 503 另附 `retry_after` / `Retry-After` 欄位。

---

## 設定檔 `config.json`

```json
{
  "eapol_test_path": "/usr/bin/eapol_test",
  "timeout": 30,
  "listen_host": "0.0.0.0",
  "listen_port": 5000,
  "default_server": "TANRC",

  "raw_log": false,
  "trust_proxy": false,
  "batch_max_workers": 10,
  "max_body_bytes": 16384,

  "rate_limit": {
    "per_ip_requests_per_minute": 30,
    "per_ip_batch_per_minute": 3,
    "global_max_subprocesses": 50,
    "global_max_batch_jobs": 5,
    "whitelist_ips": ["127.0.0.1/32", "::1/128"]
  },

  "rootca_fetch": {
    "timeout": 5,
    "max_size_bytes": 262144
  },

  "servers": {
    "TANRC": {
      "address": "4.190.160.22",
      "port": 1812,
      "secret": "testing123",
      "description": "臺灣學術網路漫遊中心",
      "types": ["eap", "non-eap"]
    }
  }
}
```

| 欄位                     | 說明                                                       |
| ------------------------ | ---------------------------------------------------------- |
| `eapol_test_path`        | `eapol_test` 執行檔路徑                                    |
| `timeout`                | 單次測試逾時秒數                                           |
| `listen_host/port`       | Flask 監聽位置                                             |
| `default_server`         | 未指定 `server` 參數時的預設                               |
| `raw_log`                | **預設 false**。公開環境不建議啟用；啟用後會回傳 `output` / `raw_output` / `config_used` 等除錯資料 |
| `trust_proxy`            | 反代後方部署時設 true，優先從 `CF-Connecting-IP`，其次 `X-Forwarded-For` / `X-Real-IP` 取真實 IP |
| `batch_max_workers`      | 單一 batch 請求內 thread pool 上限                         |
| `max_body_bytes`         | Flask `MAX_CONTENT_LENGTH`；預設 `16384`（16 KB），超過回 `413` |
| `rate_limit.*`           | Per-IP 與全域限流參數（見上節）                            |
| `rootca_fetch.timeout`   | AIA fetch timeout 秒數                                     |
| `rootca_fetch.max_size_bytes` | AIA fetch 下載大小上限                                |
| `servers.<name>`         | 單一 server 設定                                           |
| `servers.<name>.types`   | `["eap"]` / `["non-eap"]` / 兩者皆填                       |

### 環境變數

不需要任何環境變數。所有設定都從 `config.json` 讀，app 預設讀 `app.py` 旁邊的 `config.json`（容器內即 `/app/config.json`，由 compose volume 掛入）；檔案不存在時啟動會直接報錯提示。

`EAPOL_CONFIG_PATH` 仍可作為選配覆寫，指向其他設定檔；測試時 `tests/test_app.py` 用它指到 `tests/config-test.json`，不會動到實際設定。

對外 TLS / nginx 層的環境變數（`DOMAIN`、`ACME_EMAIL`、`CERTBOT_STAGING`、`TZ`）在獨立的 **eapol-nginx** repo。

---

## 安全性

- 回應的 `output` / `raw_output` 會遮蔽 server IP（替換為 `<name Server IP>`）和 shared secret（替換為 `<SHARED_SECRET>`）
- 密碼以 **hex** 寫入暫存 wpa_supplicant conf，執行後立即刪除
- `/api/servers` 不回傳 IP / secret
- `config_used` 預設不回傳（避免洩漏 ssid / identity 等 debug 資訊）
- 所有敏感端點僅接受 POST，不接受 query string 帶入帳密
- Root CA AIA fetch 會拒絕 localhost / 私網 / link-local / 雲端 metadata 位址，限制 timeout 與下載大小；每一跳重新驗 scheme / host / DNS / IP 後 pin 住單一 IP 做 TCP 連線，防 DNS rebinding / TOCTOU；HTTPS 仍用原始 hostname 做 SNI + 憑證驗證（`CERT_REQUIRED` + `check_hostname=True`）
- Per-IP rate limit + 白名單 + 全域 subprocess / batch semaphore 防止資源耗盡
- CSP 不依賴 `'unsafe-inline'`；前端邏輯全部由 `/static/` 下的外部 JS 載入
