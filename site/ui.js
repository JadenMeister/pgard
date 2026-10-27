// PGARD landing page: theme toggle, mobile menu and the GitHub star count.
// The only network request is the star count from api.github.com (3 s timeout,
// silent fallback to no number). No analytics, no cookies.
(function () {
  "use strict";

  var REPO_API = "https://api.github.com/repos/JadenMeister/pgard";
  var root = document.documentElement;

  // --- Theme toggle (the system default stays until the visitor chooses) ---
  var themeBtn = document.getElementById("theme-toggle");
  function effectiveTheme() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }
  function labelTheme() {
    if (!themeBtn) return;
    var next = effectiveTheme() === "dark" ? "light" : "dark";
    themeBtn.setAttribute("aria-label", themeBtn.getAttribute("data-label-" + next) || "");
    themeBtn.setAttribute("title", themeBtn.getAttribute("data-label-" + next) || "");
  }
  if (themeBtn) {
    labelTheme();
    themeBtn.addEventListener("click", function () {
      var next = effectiveTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try {
        localStorage.setItem("pgard-theme", next);
      } catch (e) {
        /* the choice just is not remembered */
      }
      labelTheme();
    });
  }

  // --- Mobile menu ---
  var menuBtn = document.getElementById("menu-toggle");
  var navWrap = document.getElementById("site-nav");
  if (menuBtn && navWrap) {
    var setOpen = function (open) {
      navWrap.classList.toggle("open", open);
      menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
      menuBtn.setAttribute(
        "aria-label",
        menuBtn.getAttribute(open ? "data-label-close" : "data-label-open") || "",
      );
    };
    menuBtn.addEventListener("click", function () {
      setOpen(menuBtn.getAttribute("aria-expanded") !== "true");
    });
    navWrap.addEventListener("click", function (e) {
      if (e.target && e.target.closest && e.target.closest("a")) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && menuBtn.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        menuBtn.focus();
      }
    });
  }

  // --- GitHub star count ---
  function format(n) {
    if (n >= 10000) return Math.round(n / 1000) + "k";
    if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "k";
    return String(n);
  }
  function show(n) {
    document.querySelectorAll("[data-stars]").forEach(function (el) {
      var out = el.querySelector("[data-stars-n]");
      if (out) out.textContent = format(n);
      el.hidden = false;
    });
  }
  function cached() {
    try {
      var raw = sessionStorage.getItem("pgard-stars");
      var n = raw === null ? NaN : Number(raw);
      return isFinite(n) && n >= 0 ? n : null;
    } catch (e) {
      return null;
    }
  }
  var known = cached();
  if (known !== null) {
    show(known);
  } else if (typeof fetch === "function") {
    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = setTimeout(function () {
      if (ctrl) ctrl.abort();
    }, 3000);
    fetch(REPO_API, {
      headers: { Accept: "application/vnd.github+json" },
      signal: ctrl ? ctrl.signal : undefined,
      credentials: "omit",
      referrerPolicy: "no-referrer",
    })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (j) {
        clearTimeout(timer);
        var n = j && typeof j.stargazers_count === "number" ? j.stargazers_count : null;
        if (n === null) return;
        show(n);
        try {
          sessionStorage.setItem("pgard-stars", String(n));
        } catch (e) {
          /* not cached */
        }
      })
      .catch(function () {
        clearTimeout(timer); /* silent fallback: no number */
      });
  }
})();
