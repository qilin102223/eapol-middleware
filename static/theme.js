(function() {
    try {
        var saved = localStorage.getItem("theme");
        var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        document.documentElement.setAttribute("data-theme", saved || (prefersDark ? "dark" : "light"));
    } catch (e) {}
})();

function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    var icon = document.getElementById("themeIcon");
    if (icon) icon.textContent = t === "dark" ? "light_mode" : "dark_mode";
}

function toggleTheme() {
    var cur = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
    var next = cur === "dark" ? "light" : "dark";
    try { localStorage.setItem("theme", next); } catch (e) {}
    applyTheme(next);
}

document.addEventListener("DOMContentLoaded", function() {
    var cur = document.documentElement.getAttribute("data-theme") || "light";
    var icon = document.getElementById("themeIcon");
    if (icon) icon.textContent = cur === "dark" ? "light_mode" : "dark_mode";
    var btn = document.getElementById("themeToggle");
    if (btn) btn.addEventListener("click", toggleTheme);
    requestAnimationFrame(function() { document.documentElement.classList.add("theme-ready"); });
});
