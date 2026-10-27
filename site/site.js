// PGARD landing page: tabs for the terminal demos and copy buttons.
// No network access, no storage, no third-party code. The page works without it.
(function () {
  "use strict";

  var root = document.documentElement;
  root.classList.add("js");

  // --- Tabs (WAI-ARIA tabs pattern, automatic activation) ---
  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var tabs = Array.prototype.slice.call(box.querySelectorAll('[role="tab"]'));
    var panels = tabs.map(function (t) {
      return document.getElementById(t.getAttribute("aria-controls"));
    });

    function select(index, focus) {
      tabs.forEach(function (tab, i) {
        var on = i === index;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
        if (panels[i]) panels[i].hidden = !on;
      });
      if (focus) tabs[index].focus();
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () {
        select(i, false);
      });
      tab.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowRight") next = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = tabs.length - 1;
        if (next !== null) {
          e.preventDefault();
          select(next, true);
        }
      });
    });

    select(0, false);
  });

  // --- Copy buttons ---
  function commandText(code) {
    var lines = code.querySelectorAll(".cmd-text");
    return Array.prototype.map
      .call(lines, function (el) {
        return el.textContent;
      })
      .join("\n");
  }

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "sr-copy";
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  document.querySelectorAll(".copy").forEach(function (btn) {
    var original = btn.textContent;
    var timer = 0;
    btn.addEventListener("click", function () {
      var code = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!code) return;
      var text = commandText(code);
      function done(ok) {
        if (!ok) return;
        btn.textContent = btn.getAttribute("data-copied") || "Copied";
        btn.setAttribute("data-done", "");
        clearTimeout(timer);
        timer = setTimeout(function () {
          btn.textContent = original;
          btn.removeAttribute("data-done");
        }, 1800);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () {
            done(true);
          },
          function () {
            done(fallbackCopy(text));
          },
        );
      } else {
        done(fallbackCopy(text));
      }
    });
  });
})();
