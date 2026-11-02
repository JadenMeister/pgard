// PGARD landing page: theme toggle, mobile menu, the screenshot slider, the install switch and the GitHub star count.
// The only network request is the star count from api.github.com (3 s timeout,
// silent fallback to no number). No analytics, no cookies.
(function () {
  "use strict";

  var REPO_API = "https://api.github.com/repos/JadenMeister/pgard";
  var root = document.documentElement;

  // --- Screenshot slider: arrows and dots on top of the scroll-snap track ---
  Array.prototype.forEach.call(document.querySelectorAll("[data-slider]"), function (slider) {
    var track = slider.querySelector("[data-slides]");
    var nav = slider.querySelector("[data-slider-nav]");
    if (!track || !nav) return;
    var slides = track.children;
    var dots = nav.querySelectorAll("[data-slider-go]");
    var prev = nav.querySelector("[data-slider-prev]");
    var next = nav.querySelector("[data-slider-next]");
    function current() {
      var w = track.clientWidth || 1;
      return Math.max(0, Math.min(slides.length - 1, Math.round(track.scrollLeft / w)));
    }
    function go(i) {
      var n = Math.max(0, Math.min(slides.length - 1, i));
      track.scrollTo({ left: n * track.clientWidth });
    }
    function update() {
      var i = current();
      for (var d = 0; d < dots.length; d++) {
        if (d === i) dots[d].setAttribute("aria-current", "true");
        else dots[d].removeAttribute("aria-current");
      }
      if (prev) prev.disabled = i === 0;
      if (next) next.disabled = i === slides.length - 1;
    }
    var pending = false;
    track.addEventListener("scroll", function () {
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () {
        pending = false;
        update();
      });
    });
    if (prev)
      prev.addEventListener("click", function () {
        go(current() - 1);
      });
    if (next)
      next.addEventListener("click", function () {
        go(current() + 1);
      });
    Array.prototype.forEach.call(dots, function (dot) {
      dot.addEventListener("click", function () {
        go(Number(dot.getAttribute("data-slider-go")) - 1);
      });
    });
    track.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        go(current() - 1);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        go(current() + 1);
      }
    });
    nav.hidden = false;
    update();
  });

  // --- Install switch (npm / Homebrew): tabs, arrow keys, choice shared and remembered ---
  var installKey = "pgard-install";
  var installGroups = document.querySelectorAll("[data-install]");
  function installChoice() {
    try {
      var v = localStorage.getItem(installKey);
      return v === "brew" || v === "npm" ? v : null;
    } catch (e) {
      return null;
    }
  }
  function pickInstall(which, focusIn) {
    Array.prototype.forEach.call(installGroups, function (group) {
      Array.prototype.forEach.call(group.querySelectorAll("[data-install-pick]"), function (tab) {
        var on = tab.getAttribute("data-install-pick") === which;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(tab.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
        if (on && focusIn === group) tab.focus();
      });
    });
  }
  Array.prototype.forEach.call(installGroups, function (group) {
    var tabs = group.querySelectorAll("[data-install-pick]");
    Array.prototype.forEach.call(tabs, function (tab, i) {
      function choose(which, focus) {
        pickInstall(which, focus ? group : null);
        try {
          localStorage.setItem(installKey, which);
        } catch (e) {
          /* the choice just is not remembered */
        }
      }
      tab.addEventListener("click", function () {
        choose(tab.getAttribute("data-install-pick"), false);
      });
      tab.addEventListener("keydown", function (e) {
        var n = null;
        if (e.key === "ArrowRight") n = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft") n = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") n = 0;
        else if (e.key === "End") n = tabs.length - 1;
        if (n === null) return;
        e.preventDefault();
        choose(tabs[n].getAttribute("data-install-pick"), true);
      });
    });
  });
  if (installGroups.length && installChoice()) pickInstall(installChoice(), null);

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
