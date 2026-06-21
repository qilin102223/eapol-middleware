(function() {
    "use strict";

    var certStore = {};
    var lastBatch = null;  // { data, includeRoot }

    function $(id) { return document.getElementById(id); }

    function clearChildren(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    function showError(msg) { alert(msg); }

    function httpStatusText(status) {
        if (status === 400) return "參數錯誤 (400)";
        if (status === 401) return "認證失敗 (401)";
        if (status === 404) return "找不到 (404)";
        if (status === 405) return "方法不允許 (405)";
        if (status === 408) return "請求逾時 (408)";
        if (status === 413) return "請求過大 (413)";
        if (status === 429) return "請求過多 (429)";
        if (status === 500) return "內部伺服器錯誤 (500)";
        if (status === 502) return "上游服務錯誤 (502)";
        if (status === 503) return "服務暫時無法使用 (503)";
        if (status === 504) return "伺服器回應逾時 (504)";
        return "HTTP " + status;
    }

    function b64ToPem(b64) {
        if (!b64) return "";
        return "-----BEGIN CERTIFICATE-----\n"
            + b64.match(/.{1,64}/g).join("\n")
            + "\n-----END CERTIFICATE-----\n";
    }

    function csvEscape(val) {
        var s = val == null ? "" : String(val);
        if (/[",\r\n]/.test(s)) {
            return "\"" + s.replace(/"/g, "\"\"") + "\"";
        }
        return s;
    }

    function exportCsv() {
        if (!lastBatch || !lastBatch.data) return;
        var d = lastBatch.data;
        var includeRoot = !!lastBatch.includeRoot;

        var headers = ["method", "eap_phase2", "result", "server_cn", "server_cert"];
        if (includeRoot) headers.push("root_cn", "root_cert");

        var lines = [headers.map(csvEscape).join(",")];
        for (var i = 0; i < d.results.length; i++) {
            var r = d.results[i];
            var methodName = r.type === "non-eap"
                ? (r.phase2 || "").toUpperCase()
                : (r.eap_method || "").toUpperCase();
            var phase2Name = r.type === "non-eap" ? "-" : (r.phase2 || "").toUpperCase();

            var row;
            if (r.type === "non-eap") {
                row = [methodName, phase2Name, r.result || "", "N/A", "N/A"];
                if (includeRoot) row.push("N/A", "N/A");
            } else {
                row = [
                    methodName,
                    phase2Name,
                    r.result || "",
                    r.server_cert_cn || "",
                    b64ToPem(r.server_cert_base64),
                ];
                if (includeRoot) {
                    if (r.root_ca) {
                        row.push(r.root_ca.cn || "", b64ToPem(r.root_ca.base64));
                    } else {
                        row.push("", "");
                    }
                }
            }
            lines.push(row.map(csvEscape).join(","));
        }

        // BOM so Excel reads UTF-8 correctly
        var blob = new Blob(["\ufeff" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
        // e.g. 2026-04-19T11:30:00.000Z → 2026-04-19_11-30-00
        var ts = new Date().toISOString().slice(0, 19).replace(/:/g, "-").replace("T", "_");
        var name = (d.identity || "user") + "-" + (d.server || "server") + "-" + ts + ".csv";
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = name.replace(/[^\w.\-@]/g, "_");
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function downloadCert(id) {
        var c = certStore[id];
        if (!c || !c.b64) return;
        var blob = new Blob([b64ToPem(c.b64)], { type: "application/x-pem-file" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = (c.cn || "server").replace(/[^\w.-]/g, "_") + ".pem";
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function friendlyHttpError(status, body) {
        var bodyErr = "";
        if (body && body.error) {
            bodyErr = Array.isArray(body.error) ? body.error.join("\n") : String(body.error);
        }
        return bodyErr || httpStatusText(status);

        // 先抽 body.error（後端會把參數驗證錯誤塞這裡），做為優先顯示。
        var bodyErr = "";
        if (body && body.error) {
            bodyErr = Array.isArray(body.error) ? body.error.join("\n") : String(body.error);
        }
        if (status === 400) {
            // 參數錯誤（後端通常會帶訊息）
            return bodyErr || "參數錯誤 (400)：請檢查輸入格式";
        }
        if (status === 401) {
            // 批次模式不會在最外層回 401，但萬一 proxy / CDN 擋掉時給個說明
            return "認證失敗 (401)";
        }
        if (status === 404) return "找不到路由 (404)";
        if (status === 405) return "方法不允許（請使用 POST）";
        if (status === 408) return "逾時 (408)，請稍後再試";
        if (status === 413) return "請求內容過大 (413)：請確認帳密長度";
        if (status === 429) return "請求過於頻繁 (429)，請稍後再試";
        if (status === 500) return "伺服器內部錯誤 (500)：請稍微等候再試";
        if (status === 502) return "上游服務無法連線 (502)";
        if (status === 503) return "系統資源忙碌 (503)，請稍後再試";
        if (status === 504) {
            // 批次呼叫後端不會主動回 504，但 reverse proxy 可能會；給一致說明
            return "認證逾時 (504)：RADIUS 伺服器未在時限內回應。請稍後再試。";
        }
        if (status >= 500) return "伺服器錯誤 (" + status + ")";
        if (bodyErr) return bodyErr;
        return "HTTP " + status;
    }

    function buildSummaryLine(server, identity, passed, total) {
        var line = $("summaryLine");
        clearChildren(line);
        line.appendChild(document.createTextNode("Server: "));
        var s1 = document.createElement("strong"); s1.textContent = server; line.appendChild(s1);
        // \u00a0 = non-breaking space (keep as escape: invisible chars stay readable in diffs)
        line.appendChild(document.createTextNode(" \u00a0|\u00a0 Identity: "));
        var s2 = document.createElement("strong"); s2.textContent = identity; line.appendChild(s2);
        line.appendChild(document.createTextNode(" \u00a0|\u00a0 通過: "));
        var s3 = document.createElement("strong"); s3.textContent = passed + "/" + total; line.appendChild(s3);
    }

    function textTd(txt) {
        var td = document.createElement("td");
        td.textContent = txt == null ? "" : String(txt);
        return td;
    }

    function badgeTd(result) {
        var td = document.createElement("td");
        var cls = (result === "SUCCESS" || result === "FAILURE" || result === "TIMEOUT")
            ? result.toLowerCase() : "error";
        var span = document.createElement("span");
        span.className = "badge " + cls;
        span.textContent = result;
        td.appendChild(span);
        return td;
    }

    function dlTd(certId, cls) {
        var td = document.createElement("td");
        if (cls) td.className = cls;
        if (!certId) { td.textContent = "-"; return td; }
        var a = document.createElement("a");
        a.className = "dl-link";
        a.textContent = "下載 .pem";
        a.setAttribute("data-cert-id", certId);
        a.setAttribute("role", "button");
        a.setAttribute("tabindex", "0");
        a.addEventListener("click", function() { downloadCert(this.getAttribute("data-cert-id")); });
        td.appendChild(a);
        return td;
    }

    function naTd(cls) {
        var td = document.createElement("td");
        if (cls) td.className = cls;
        td.textContent = "N/A";
        return td;
    }

    function renderResults(d) {
        var tbody = $("resultBody");
        clearChildren(tbody);
        certStore = {};

        var showRootCol = $("rootca").checked;
        $("resultTable").classList.toggle("no-root", !showRootCol);

        for (var i = 0; i < d.results.length; i++) {
            var r = d.results[i];
            var tr = document.createElement("tr");
            tr.className = (r.result || "").toLowerCase();

            var methodName = r.type === "non-eap"
                ? (r.phase2 || "").toUpperCase()
                : (r.eap_method || "").toUpperCase();
            var phase2Name = r.type === "non-eap" ? "-" : (r.phase2 || "").toUpperCase();

            tr.appendChild(textTd(methodName));
            tr.appendChild(textTd(phase2Name));
            tr.appendChild(badgeTd(r.result));

            if (r.type === "non-eap") {
                tr.appendChild(textTd("N/A"));
                tr.appendChild(naTd());
            } else {
                tr.appendChild(textTd(r.server_cert_cn || "-"));
                if (r.server_cert_base64) {
                    var certId = "cert_" + i;
                    certStore[certId] = { b64: r.server_cert_base64, cn: r.server_cert_cn };
                    tr.appendChild(dlTd(certId));
                } else {
                    tr.appendChild(textTd("-"));
                }
            }

            if (r.type === "non-eap") {
                tr.appendChild(naTd("rootca-col"));
                tr.appendChild(naTd("rootca-col"));
            } else if (r.root_ca) {
                var rid = "root_" + i;
                certStore[rid] = { b64: r.root_ca.base64, cn: r.root_ca.cn };
                var rootCnTd = document.createElement("td");
                rootCnTd.className = "rootca-col";
                rootCnTd.textContent = r.root_ca.cn || "(no CN)";
                tr.appendChild(rootCnTd);
                tr.appendChild(dlTd(rid, "rootca-col"));
            } else {
                var cn = document.createElement("td");
                cn.className = "rootca-col"; cn.textContent = "-";
                tr.appendChild(cn);
                var dl = document.createElement("td");
                dl.className = "rootca-col"; dl.textContent = "-";
                tr.appendChild(dl);
            }

            tbody.appendChild(tr);
        }
    }

    async function runBatch() {
        var username = $("username").value.trim();
        var password = $("password").value.trim();
        if (!username || !password) { showError("請填寫帳號和密碼"); return; }

        var body = {
            username: username,
            password: password,
            server: $("server").value,
            parallel: $("parallel").checked,
            rootca: $("rootca").checked,
        };
        var anon = $("anonymous_identity").value.trim();
        if (anon) body.anonymous_identity = anon;

        var btn = $("testBtn");
        var spinner = $("spinner");
        var resultArea = $("resultArea");

        btn.disabled = true;
        spinner.style.display = "block";
        resultArea.classList.add("hidden");

        try {
            var resp = await fetch("/api/batch", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            var d = null;
            try { d = await resp.json(); } catch (e) { d = null; }
            if (!resp.ok) { showError(friendlyHttpError(resp.status, d)); return; }
            if (d && d.error) { showError(Array.isArray(d.error) ? d.error.join("\n") : d.error); return; }

            var total = d.results.length;
            var passed = 0;
            for (var i = 0; i < total; i++) if (d.results[i].result === "SUCCESS") passed++;
            buildSummaryLine(d.server, d.identity, passed, total);
            renderResults(d);
            lastBatch = { data: d, includeRoot: $("rootca").checked };
            resultArea.classList.remove("hidden");
        } catch (err) {
            showError("請求失敗: " + (err && err.message ? err.message : String(err)));
        } finally {
            btn.disabled = false;
            spinner.style.display = "none";
        }
    }

    function init() {
        $("testBtn").addEventListener("click", runBatch);
        $("exportCsvBtn").addEventListener("click", exportCsv);

        fetch("/api/servers").then(function(r) { return r.json(); }).then(function(data) {
            var sel = $("server");
            var servers = data.servers || {};
            for (var name in servers) {
                if (!Object.prototype.hasOwnProperty.call(servers, name)) continue;
                var info = servers[name];
                var opt = document.createElement("option");
                opt.value = name;
                opt.textContent = info.description ? info.description + " (" + name + ")" : name;
                if (name === data.default) opt.selected = true;
                sel.appendChild(opt);
            }
        }).catch(function() {});
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
