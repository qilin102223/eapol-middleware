(function() {
    "use strict";

    var $ = UI.$;
    var clearChildren = UI.clearChildren;

    var methodData = {};
    var allServers = {};
    var currentMode = "eap";
    var certStore = {};

    function el(tag, opts) {
        var e = document.createElement(tag);
        if (!opts) return e;
        if (opts.text != null) e.textContent = opts.text;
        if (opts.className) e.className = opts.className;
        if (opts.attrs) {
            for (var k in opts.attrs) {
                if (Object.prototype.hasOwnProperty.call(opts.attrs, k)) e.setAttribute(k, opts.attrs[k]);
            }
        }
        if (opts.children) {
            for (var i = 0; i < opts.children.length; i++) {
                if (opts.children[i]) e.appendChild(opts.children[i]);
            }
        }
        return e;
    }

    function iconSpan(name, className) {
        return el("span", { className: "material-symbols-outlined " + (className || ""), text: name });
    }

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

    function setMode(mode) {
        currentMode = mode;
        clearError();
        $("modeEap").className = "seg-btn" + (mode === "eap" ? " active" : "");
        $("modeRad").className = "seg-btn" + (mode === "rad" ? " active" : "");
        $("eapFields").classList.toggle("hidden", mode !== "eap");
        $("radFields").classList.toggle("hidden", mode !== "rad");
        $("resultArea").classList.add("hidden");
        var typeKey = mode === "eap" ? "eap" : "non-eap";
        var sel = $("server");
        var prev = sel.value;
        clearChildren(sel);
        for (var name in allServers) {
            if (!Object.prototype.hasOwnProperty.call(allServers, name)) continue;
            var info = allServers[name];
            if (info.types && info.types.indexOf(typeKey) < 0) continue;
            var opt = document.createElement("option");
            opt.value = name;
            opt.textContent = info.description ? info.description + " (" + name + ")" : name;
            sel.appendChild(opt);
        }
        for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === prev) { sel.value = prev; break; }
        }
    }

    function updatePhase2() {
        var eap = $("eap_method").value;
        var sel = $("phase2");
        clearChildren(sel);
        if (!methodData[eap]) return;
        var opts = methodData[eap].phase2_options;
        for (var i = 0; i < opts.length; i++) {
            var p = opts[i];
            var opt = document.createElement("option");
            opt.value = p;
            opt.textContent = p.toUpperCase();
            if (p === methodData[eap].default_phase2) opt.selected = true;
            sel.appendChild(opt);
        }
    }

    function buildStatusBadge(result) {
        var badge = $("statusBadge");
        clearChildren(badge);
        if (result === "SUCCESS") {
            badge.className = "status-chip ok";
            badge.appendChild(iconSpan("check_circle", "icon-sm"));
            badge.appendChild(document.createTextNode("認證成功 (SUCCESS)"));
        } else if (result === "TIMEOUT") {
            badge.className = "status-chip timeout";
            badge.appendChild(iconSpan("schedule", "icon-sm"));
            badge.appendChild(document.createTextNode("連線逾時 (TIMEOUT)"));
        } else {
            badge.className = "status-chip fail";
            badge.appendChild(iconSpan("cancel", "icon-sm"));
            badge.appendChild(document.createTextNode("認證失敗 (" + result + ")"));
        }
    }

    function buildSummaryTable(rows) {
        var tbl = $("summaryTable");
        clearChildren(tbl);
        for (var i = 0; i < rows.length; i++) {
            var tr = document.createElement("tr");
            var tdKey = document.createElement("td");
            tdKey.textContent = rows[i][0];
            var tdVal = document.createElement("td");
            tdVal.textContent = rows[i][1] == null ? "" : String(rows[i][1]);
            tr.appendChild(tdKey);
            tr.appendChild(tdVal);
            tbl.appendChild(tr);
        }
    }

    function buildCertItem(depthLabel, cn, subject, certId, extraClass) {
        var item = el("div", { className: "cert-item" + (extraClass ? " " + extraClass : "") });
        var head = el("div", { className: "cert-head" });
        head.appendChild(el("span", { className: "cert-depth", text: depthLabel }));
        if (certId) {
            var btn = UI.pemButton();
            btn.setAttribute("data-cert-id", certId);
            btn.addEventListener("click", function() {
                var c = certStore[this.getAttribute("data-cert-id")];
                if (c) UI.downloadPem(c.b64, c.cn, "cert");
            });
            head.appendChild(btn);
        }
        item.appendChild(head);
        item.appendChild(el("div", { className: "cert-cn", text: cn || "(no CN)" }));
        item.appendChild(el("div", { className: "cert-subject", text: subject || "" }));
        return item;
    }

    function renderCerts(d, isEap) {
        var certArea = $("certArea");
        var certList = $("certList");
        clearChildren(certList);
        var chain = (isEap && d.server_cert_chain && d.server_cert_chain.length > 0) ? d.server_cert_chain : null;
        if (chain) {
            certArea.classList.remove("hidden");
            for (var i = 0; i < chain.length; i++) {
                var c = chain[i];
                var id = "cert_" + i;
                certStore[id] = { b64: c.base64, cn: c.cn };
                var depthLabel = i === 0 ? "leaf" : "intermediate " + i;
                certList.appendChild(buildCertItem(depthLabel, c.cn, c.subject, id));
            }
        } else if (isEap && d.server_certs && d.server_certs.length > 0) {
            certArea.classList.remove("hidden");
            for (var j = 0; j < d.server_certs.length; j++) {
                var sc = d.server_certs[j];
                certList.appendChild(buildCertItem("depth=" + sc.depth, sc.cn, sc.subject, null));
            }
        } else {
            certArea.classList.add("hidden");
        }

        var rootCaArea = $("rootCaArea");
        var rootCaBox = $("rootCaBox");
        clearChildren(rootCaBox);
        if (isEap && d.root_ca) {
            certStore["root_ca"] = { b64: d.root_ca.base64, cn: d.root_ca.cn };
            rootCaArea.classList.remove("hidden");
            rootCaBox.appendChild(buildCertItem("root", d.root_ca.cn, d.root_ca.subject, "root_ca", "root-ca"));
        } else {
            rootCaArea.classList.add("hidden");
        }
    }

    function showResult(d, isEap) {
        clearError();
        buildStatusBadge(d.result);
        var rows = [["RADIUS Server", d.server], ["Identity", d.identity]];
        if (isEap) {
            rows.push(["Anonymous Identity", d.anonymous_identity || "(未設定)"]);
            rows.push(["EAP 方法", (d.eap_method || "").toUpperCase()]);
            rows.push(["Phase 2", (d.phase2 || "").toUpperCase()]);
        } else {
            rows.push(["方法", (d.method || "").toUpperCase()]);
        }
        rows.push(["認證結果", d.result]);
        buildSummaryTable(rows);

        certStore = {};
        renderCerts(d, isEap);

        var rawArea = $("rawArea");
        var rawOutput = $("rawOutput");
        if (d.raw_output) {
            rawOutput.textContent = d.raw_output;
            rawArea.classList.remove("hidden");
        } else {
            rawOutput.textContent = "";
            rawArea.classList.add("hidden");
        }

        $("resultArea").classList.remove("hidden");
    }

    async function runTest() {
        var username = $("username").value.trim();
        var password = $("password").value.trim();
        if (!username || !password) { showError("請填寫帳號和密碼"); return; }

        var btn = $("testBtn");
        btn.disabled = true;
        $("spinner").classList.remove("hidden");
        clearError();
        $("resultArea").classList.add("hidden");

        try {
            var url, body;
            if (currentMode === "eap") {
                url = "/api/eapol-test/structured";
                body = {
                    username: username, password: password,
                    eap_method: $("eap_method").value,
                    phase2: $("phase2").value,
                    server: $("server").value,
                    rootca: $("rootca").checked,
                };
                var anon = $("anonymous_identity").value.trim();
                if (anon) body.anonymous_identity = anon;
            } else {
                url = "/api/radtest";
                body = {
                    username: username, password: password,
                    method: $("rad_method").value,
                    server: $("server").value,
                };
            }
            var resp = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            var d = null;
            try { d = await resp.json(); } catch (e) { d = null; }
            // 401 (FAILURE) / 504 (TIMEOUT) 後端會回結構化 body，帶 result 欄位；
            // 此時直接畫在結果卡上，用 badge 呈現，比單純 alert 更直覺。
            if (d && typeof d.result === "string") {
                showResult(d, currentMode === "eap");
                return;
            }
            var bodyErr = UI.errorText(d);
            if (!resp.ok) {
                showError(bodyErr || UI.httpStatusText(resp.status));
                return;
            }
            if (bodyErr) { showError(bodyErr); return; }
            showResult(d, currentMode === "eap");
        } catch (err) {
            showError("請求失敗: " + (err && err.message ? err.message : String(err)));
        } finally {
            btn.disabled = false;
            $("spinner").classList.add("hidden");
        }
    }

    function init() {
        $("modeEap").addEventListener("click", function() { setMode("eap"); });
        $("modeRad").addEventListener("click", function() { setMode("rad"); });
        $("eap_method").addEventListener("change", updatePhase2);
        $("testBtn").addEventListener("click", runTest);

        fetch("/api/servers").then(function(r) { return r.json(); }).then(function(data) {
            allServers = data.servers || {};
            setMode("eap");
            var sel = $("server");
            for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === data.default) { sel.value = data.default; break; }
            }
        }).catch(function() {});

        fetch("/api/supported-methods").then(function(r) { return r.json(); }).then(function(data) {
            methodData = data.methods || {};
            var sel = $("eap_method");
            for (var m in methodData) {
                if (!Object.prototype.hasOwnProperty.call(methodData, m)) continue;
                var opt = document.createElement("option");
                opt.value = m;
                opt.textContent = m.toUpperCase();
                sel.appendChild(opt);
            }
            updatePhase2();
        }).catch(function() {});
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
