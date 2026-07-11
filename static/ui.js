/* 共用 UI 工具與 Material 漣漪效果，供 index.js / batch.js 使用。 */
(function() {
    "use strict";

    /* 狀態碼 → 使用者文案。這是「後端沒給 error body」時的備援 —
       502/504/429 可能由 reverse proxy 直接回應，不會有 JSON body。
       後端有給訊息時一律以 body 為準（見 errorText）。 */
    var HTTP_STATUS_TEXT = {
        400: "參數錯誤 (400)：請檢查輸入格式",
        401: "認證失敗 (401)",
        404: "找不到 (404)",
        405: "方法不允許 (405)",
        408: "請求逾時 (408)，請稍後再試",
        413: "請求內容過大 (413)",
        429: "請求過於頻繁 (429)，請稍後再試",
        500: "內部伺服器錯誤 (500)，請稍後再試",
        502: "上游服務無法連線 (502)",
        503: "服務暫時無法使用 (503)，請稍後再試",
        504: "伺服器回應逾時 (504)：RADIUS 伺服器未在時限內回應",
    };

    var UI = window.UI = {
        $: function(id) { return document.getElementById(id); },

        clearChildren: function(el) {
            while (el.firstChild) el.removeChild(el.firstChild);
        },

        httpStatusText: function(status) {
            if (HTTP_STATUS_TEXT[status]) return HTTP_STATUS_TEXT[status];
            if (status >= 500) return "伺服器錯誤 (" + status + ")";
            if (status >= 400) return "請求錯誤 (" + status + ")";
            return "HTTP " + status;
        },

        /* 後端錯誤 body（{error: string|string[]}）轉為顯示文字，無則回空字串 */
        errorText: function(body) {
            if (!body || !body.error) return "";
            return Array.isArray(body.error) ? body.error.join("\n") : String(body.error);
        },

        b64ToPem: function(b64) {
            if (!b64) return "";
            return "-----BEGIN CERTIFICATE-----\n"
                + b64.match(/.{1,64}/g).join("\n")
                + "\n-----END CERTIFICATE-----\n";
        },

        downloadBlob: function(blob, filename) {
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            a.click();
            URL.revokeObjectURL(a.href);
        },

        downloadPem: function(b64, cn, fallbackName) {
            if (!b64) return;
            var blob = new Blob([UI.b64ToPem(b64)], { type: "application/x-pem-file" });
            UI.downloadBlob(blob, (cn || fallbackName).replace(/[^\w.-]/g, "_") + ".pem");
        },

        /* 下載 .pem 小按鈕；點擊行為由呼叫端掛上 */
        pemButton: function() {
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "dl-btn";
            btn.setAttribute("aria-label", "下載 .pem");
            var icon = document.createElement("span");
            icon.className = "material-symbols-outlined";
            icon.setAttribute("aria-hidden", "true");
            icon.textContent = "download";
            btn.appendChild(icon);
            btn.appendChild(document.createTextNode(".pem"));
            return btn;
        },
    };

    /* Material 漣漪：pointerdown 事件委派，動態產生的按鈕也適用 */
    document.addEventListener("pointerdown", function(e) {
        var host = e.target.closest && e.target.closest(".btn, .seg-btn, .nav-btn, .theme-toggle, .dl-btn");
        if (!host || host.disabled) return;
        var rect = host.getBoundingClientRect();
        var d = Math.max(rect.width, rect.height) * 2;
        var ripple = document.createElement("span");
        ripple.className = "ripple";
        ripple.style.width = ripple.style.height = d + "px";
        ripple.style.left = (e.clientX - rect.left - d / 2) + "px";
        ripple.style.top = (e.clientY - rect.top - d / 2) + "px";
        host.appendChild(ripple);
        ripple.addEventListener("animationend", function() { ripple.remove(); });
        setTimeout(function() { ripple.remove(); }, 700); // animationend 沒觸發時的保險
    });
})();
