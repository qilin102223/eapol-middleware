# eapol_test Middleware API

透過 HTTP API 進行 802.1X EAP 及傳統 RADIUS 認證測試。支援多台 RADIUS server。

## 功能

- 802.1X EAP 認證測試（PEAP / TTLS + 各種 Phase 2）
- 傳統 RADIUS 認證測試（PAP / CHAP / MSCHAP）
- 批次測試所有方法組合（EAP + 非 EAP）
- 伺服器憑證擷取：完整鏈（leaf → root 排序）、每張憑證下載、CN 解析
- **Root CA 追溯**：沿憑證 AIA 走鏈 + 系統信任庫，定位自簽根憑證（例如 Let's Encrypt → ISRG Root X1）
- 多 RADIUS server 管理，依 server 限制支援的測試類型（`eap` / `non-eap`）
- 輸出自動遮蔽 server IP 和 shared secret

## 設定

編輯 `config.json`：

```json
{
    "eapol_test_path": "/usr/bin/eapol_test",
    "timeout": 30,
    "listen_host": "0.0.0.0",
    "listen_port": 5000,
    "default_server": "my-radius",

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
        "my-radius": {
            "address": "192.168.1.1",
            "port": 1812,
            "secret": "testing123",
            "description": "主要 RADIUS",
            "types": ["eap", "non-eap"]
        },
        "eap-only": {
            "address": "192.168.1.2",
            "port": 1812,
            "secret": "secret456",
            "description": "僅 EAP",
            "types": ["eap"]
        }
    }
}
```

- `types` 可選值：`eap`（802.1X EAP）、`non-eap`（傳統 RADIUS PAP/CHAP/MSCHAP）。
- `raw_log`：**預設 false**。啟用後 API 才會回傳 `output` / `raw_output` / `config_used` 這類除錯資料。公開環境不建議啟用。
- `trust_proxy`：部署在 nginx / 其他反代後方時設 `true`，app 會優先解析 `CF-Connecting-IP`、其次 `X-Forwarded-For` / `X-Real-IP` 取真實來源 IP。
- `rate_limit.whitelist_ips`：支援單一 IP 或 CIDR；白名單 IP 可跳過 per-IP 限制，但**無法**跳過全域 subprocess / batch semaphore。
- `rate_limit.global_max_*`：全域資源上限；超出時回 `503 Service Unavailable`。
- `max_body_bytes`：request body 上限（預設 16 KB）；超過直接回 `413 Request Entity Too Large`。
- Rate limit in-memory 狀態表每 60 秒掃一次，清掉過期且空的 IP bucket，避免大量不同 IP 撐爆 dict。
- Root CA AIA fetch 遇 3xx redirect 會對每一跳重新做 scheme / host / DNS / IP SSRF 檢查；上限 5 次，超過或重驗失敗即放棄。
- Root CA AIA fetch 改為 **IP-pinned**：`_resolve_and_check()` 解析 DNS 後鎖定單一 IP，`http.client.HTTPConnection` / `HTTPSConnection` subclass 在 `connect()` 只 `socket.create_connection((pinned_ip, port))`，不讓底層再次 DNS 查詢。封阻 validate → connect 之間 DNS rebinding / TOCTOU 替換攻擊。HTTPS 仍以原始 hostname 做 SNI 與憑證驗證（`ssl.create_default_context()`，`CERT_REQUIRED` + `check_hostname=True`），不會因為連 IP 而關掉 TLS 驗證。

### 環境變數

沒有。所有設定都在 `config.json`，app 預設讀 `app.py` 旁邊的 `config.json`（容器內即 `/app/config.json`，由 compose volume 掛入）。`EAPOL_CONFIG_PATH` 仍可作為選配覆寫（測試套件用它指向 `tests/config-test.json`）。

對外 TLS / nginx 層的環境變數（`DOMAIN`、`ACME_EMAIL` 等）在獨立的 **eapol-nginx** repo。

## 啟動

```bash
cp config.example.json config.json && vim config.json   # 填 RADIUS server 資訊
docker compose up -d --build
curl http://localhost:5000/api/health
```

就這樣。gunicorn（`-w 4 --threads 25`，100 concurrent slot）listen 在 `127.0.0.1:5000`。

重啟（停容器 → 重建 → 重開 → 等健康檢查）：

```bash
./run.sh
```

- 修改 `app.py` 或 `templates/*` 後重跑 `./run.sh`（Dockerfile 是 COPY 不是 volume）
- 只綁 loopback；要直接對 LAN 開放的話，把 `docker-compose.yml` 的 ports 改成 `"5000:5000"`
- 對 RADIUS server 的測試流量從容器經 Docker NAT 出去，對端看到的來源 IP 是宿主機 IP；要做來源白名單就白名單宿主機

### 對外公開（TLS / 網域）

對外層（Let's Encrypt 自動續期、Cloudflare origin allowlist、連線數限制、依網域分流）在獨立的 **eapol-nginx** repo，會反代 `127.0.0.1:5000`：

```
internet → :80,:443 nginx（eapol-nginx repo）→ 127.0.0.1:5000 eapol-middleware (gunicorn)
```

1. 這裡 `docker compose up -d --build`
2. 到 eapol-nginx repo 跑 `./run.sh`
3. `config.json` 設 `trust_proxy: true`，app 會解析 `CF-Connecting-IP` / `X-Forwarded-For` / `X-Real-IP` 取得真實來源 IP

**容量**：超過 100 concurrent 的請求在 socket backlog 排隊（`--backlog 2048`），client 看到 pending、不會 503。生產環境建議監控常態 API 調用即可，Batch 盡量少用（一個 batch parallel=true 會 fork 13 個 subprocess）。

**更新部署**：`git pull && ./run.sh`

### 測試

```bash
./run-tests.sh
```

會把 `tests/` / `app.py` / `config.example.json` copy 進跑中的 container，用 `python3 -m unittest discover` 執行。測試用 `EAPOL_CONFIG_PATH` 指向 `tests/config-test.json`（由測試套件動態寫入），不會動到正式 `config.json`。涵蓋：

- **端點與參數**：POST-only 限制、query string 帶帳密被拒、missing parameter 400 錯誤形狀、`server.types` 過濾、未知 server、`/api/servers` 不洩露 IP/secret
- **安全 headers / CSP**：HTML 上的完整 header 組、敏感 API `Cache-Control: no-store`、HTML 模板無 inline `<script>` / `on*=` 事件、全部 JS 走 `/static/*.js` 外部載入
- **Rate limit**：per-IP 429 + Retry-After、batch 獨立 bucket、白名單 `/32` 與 CIDR 繞過、`trust_proxy` 對 `CF-Connecting-IP` / `X-Forwarded-For` / `X-Real-IP` 的尊重/忽略、bucket TTL 清理
- **全域資源保護**：subprocess / batch semaphore、batch queue 滿 503、`max_body_bytes` 413 回應形狀
- **SSRF 防護**：localhost / RFC1918 / link-local / 雲端 metadata 阻擋、非 http(s) scheme 阻擋、redirect 每一跳重新驗證、redirect 次數上限
- **DNS rebinding / TOCTOU**：`_resolve_and_check` pin IP、多 A record 混雜公私網整串拒絕、實際 TCP 連線到 pinned IP 而非重新解析的 loopback、HTTPS SNI 與憑證驗證（`CERT_REQUIRED` + `check_hostname=True`）保留、per-hop 重驗拒絕 rebind 到私網
- **Config 行為**：預設值、缺漏欄位、`raw_log` 預設關閉與開啟、`whitelist_ips` 多格式處理、`rootca_fetch.*` 套用、`config.example.json` 與 app 預設同步
- **核心 helper**：`mask_server_ip` 遮蔽 IP + secret、`build_eapol_conf` hex-encode 帳密 + PEAP phase1、`determine_auth_result` / `determine_radtest_result` 輸出判讀、cert subject / PEM chain 解析、自簽憑證直接回傳
- **Batch 端點**：13 組合完整展開、parallel on/off 一致、EAP-only / non-eap-only server 過濾、`rootca=true` 時同 PEM cache（僅查一次）
- **前端契約**：`/` 與 `/batch` 模板上 JS 需要的 DOM id 都在、外部 JS 唯一、batch.js CSV header 順序 (`method,eap_phase2,result,server_cn,server_cert[,root_cn,root_cert]`)、UTF-8 BOM、RFC4180 quote/escape、檔名 `<identity>-<server>-<ts>.csv` + `@` 保留、b64→PEM 64 字元換行、index.js API 路由與 `modeEap/modeRad` 切換綁定

共 120 項。（nginx 層的設定契約測試已隨 nginx 拆到 eapol-nginx repo）

## API 摘要

敏感端點（`/api/eapol-test`、`/api/eapol-test/structured`、`/api/radtest`、`/api/batch`）**僅接受 POST**。
傳參方式：JSON body（建議）或 form POST；不再接受透過 query string 帶入帳密（GET 會回 `405 Method Not Allowed`）。
所有端點接受 `server` 參數指定 RADIUS server，不填用 default。

| Method | Path                         | 說明                                       |
| ------ | ---------------------------- | ------------------------------------------ |
| GET    | `/api/health`                | 健康檢查                                   |
| GET    | `/api/servers`               | 列出可用 server（不含 IP/secret）          |
| GET    | `/api/supported-methods`     | EAP 方法與 Phase 2 對照                    |
| POST   | `/api/eapol-test`            | 802.1X EAP（回傳原始輸出）                 |
| POST   | `/api/eapol-test/structured` | 802.1X EAP（結構化；含憑證鏈、Root CA）    |
| POST   | `/api/radtest`               | 傳統 RADIUS（PAP/CHAP/MSCHAP）             |
| POST   | `/api/batch`                 | 批次所有方法（依 server 支援類型）         |
| GET    | `/`                          | 單一測試前端                               |
| GET    | `/batch`                     | 批次測試前端                               |

### Rate Limit / 資源保護

- Per-IP：`/api/eapol-test*` 與 `/api/radtest` 預設 30 req/min/IP；`/api/batch` 預設 3 req/min/IP。超出回 `429` + `Retry-After`。
- 白名單 IP（`rate_limit.whitelist_ips`）可跳過 per-IP，但**無法**跳過全域保護。
- 全域 subprocess / batch job 上限以 semaphore 保護；超出回 `503` + `Retry-After`。
- 前端遇到 429 / 503 / 408 會顯示可理解的中文訊息，不會靜默失敗。

### 共用參數

- `username`, `password` — 必填
- `server` — 選填，未填用 `default_server`
- `eap_method`（`peap` / `ttls`）、`phase2`（依 eap_method）— EAP 端點必填
- `method`（`pap` / `chap` / `mschap`）— radtest 端點必填
- `anonymous_identity` — EAP 選填
- `parallel`（bool，預設 true）— batch 選填
- **`rootca`（bool，預設 false）— `/api/eapol-test`、`/api/eapol-test/structured`、`/api/batch` 可用。開啟後伺服器會沿 AIA CA Issuers 與系統信任庫追溯出自簽根憑證，加入回傳資料。`/api/radtest` 不支援（無 TLS）。**

### Root CA 追溯規則

1. 若伺服器送的憑證鏈內有自簽憑證（issuer == subject），直接回傳那張
2. 否則從鏈中最高的 intermediate 開始，沿 AIA CA Issuers URL 向上 fetch
3. AIA 缺失時，用系統信任庫 `/etc/ssl/certs/ca-certificates.crt` 以 issuer DN 比對
4. 最高深度 8 層，防迴圈

### 範例

```
POST /api/eapol-test/structured
Content-Type: application/json
{"username":"user@example.com","password":"pass","eap_method":"peap","phase2":"mschapv2","server":"my-radius","rootca":true}
```

```
POST /api/batch
Content-Type: application/json
{"username":"user@example.com","password":"pass","server":"my-radius","rootca":true}
```

完整 API 文件見 [API.md](API.md)。

## 前端頁面

- `/` — 單一測試（可切 EAP / 傳統 RADIUS）
  - 顯示完整憑證鏈（leaf → intermediates）每張可下載 `.pem`
  - 勾選「追溯 Root CA」後顯示並可下載 root
- `/batch` — 批次測試，結果表格
  - 每個 EAP 方法顯示 leaf CN 與下載連結
  - 勾選「追溯 Root CA」後表格新增 Root CA / Root 下載兩欄（每個 EAP 方法各自一張，同條鏈會快取只走一次）

## 技術細節

- Base image：`debian:trixie-slim`
- Docker build 預設用 `DEBIAN_MIRROR=http://mirror.twds.com.tw/debian`，可用 `--build-arg DEBIAN_MIRROR=...` 覆寫；image 內不放任何 config，正式 `config.json` 由 compose volume 掛載，避免把 shared secret bake 進 image layer
- 依賴：`python3-flask`、`python3-gunicorn`、`python3-cryptography`、`eapoltest`、`freeradius-utils`、`ca-certificates`
- Root CA 追溯以 Python `cryptography` 解析 X.509；相容 cryptography < 39（手動切 PEM 多張憑證）
- AIA fetch 以 `http.client` + IP pinning 實作；timeout 與下載大小由 `rootca_fetch.*` 控制；主機名先經 `getaddrinfo` 解析後檢查，拒絕 localhost / 私網 / link-local / 雲端 metadata 位址，並把解析出的 IP pin 住後直接連線，不留 DNS rebinding 空間；HTTPS 以原始 hostname 做 SNI + 憑證驗證
- Batch 內同一條憑證鏈只查一次 root（以 PEM 字串做 cache key）
- CSP（由 Flask `@app.after_request` 在 app 層加上，無 `'unsafe-inline'`）：所有前端 JS / CSS 由 `/static/` 下的外部檔案提供
- Per-IP rate limit、白名單、全域 subprocess / batch semaphore、SSRF 檢查皆在 Flask / app 層實作，不依賴 nginx
