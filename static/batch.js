(function() {
    "use strict";

    var $ = UI.$;
    var clearChildren = UI.clearChildren;

    var certStore = {};
    var lastBatch = null;  // { data, includeRoot }

    function clearError() {
        var box = $("errorBox");
        box.textContent = "";
        box.classList.add("hidden");
    }

    function showError(msg) {
        var box = $("errorBox");
        box.textContent = msg || "";
        box.classList.remove("hidden");
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
                    UI.b64ToPem(r.server_cert_base64),
                ];
                if (includeRoot) {
                    if (r.root_ca) {
                        row.push(r.root_ca.cn || "", UI.b64ToPem(r.root_ca.base64));
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
        UI.downloadBlob(blob, name.replace(/[^\w.\-@]/g, "_"));
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
        var btn = UI.pemButton();
        btn.setAttribute("data-cert-id", certId);
        btn.addEventListener("click", function() {
            var c = certStore[this.getAttribute("data-cert-id")];
            if (c) UI.downloadPem(c.b64, c.cn, "server");
        });
        td.appendChild(btn);
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
            // stagger 進場動畫，最多延遲 12 列避免久等
            tr.style.setProperty("--row-index", Math.min(i, 12));

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
        btn.disabled = true;
        $("spinner").classList.remove("hidden");
        clearError();
        $("resultArea").classList.add("hidden");

        try {
            var resp = await fetch("/api/batch", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            var d = null;
            try { d = await resp.json(); } catch (e) { d = null; }
            var bodyErr = UI.errorText(d);
            if (!resp.ok) { showError(bodyErr || UI.httpStatusText(resp.status)); return; }
            if (bodyErr) { showError(bodyErr); return; }

            var total = d.results.length;
            var passed = 0;
            for (var i = 0; i < total; i++) if (d.results[i].result === "SUCCESS") passed++;
            buildSummaryLine(d.server, d.identity, passed, total);
            renderResults(d);
            lastBatch = { data: d, includeRoot: $("rootca").checked };
            $("resultArea").classList.remove("hidden");
        } catch (err) {
            showError("請求失敗: " + (err && err.message ? err.message : String(err)));
        } finally {
            btn.disabled = false;
            $("spinner").classList.add("hidden");
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
