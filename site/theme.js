// Applies the saved theme before first paint. Loaded synchronously in <head>.
// Without a saved choice the system setting (prefers-color-scheme) decides.
(function () {
  // Marks that scripts run, so the CSS can lay out the tabs before first paint.
  document.documentElement.classList.add("js");
  try {
    var t = localStorage.getItem("pgard-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    /* storage unavailable: keep the system default */
  }
})();
