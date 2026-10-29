import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { takeTokenFromLocation } from "./api/client";
import { App } from "./app/App";
import { canonicalHash } from "./features/findings/filter-url";
import { I18nProvider } from "./i18n/I18nProvider";
import "./styles/tokens.css";
import "./styles/app.css";

// The fragment may carry a view and filters next to the token. The token leaves the address
// first; only the allow-listed view and filter keys are put back (never the original fragment).
const restoredHash = canonicalHash(window.location.hash);
takeTokenFromLocation(window.location, window.history);
if (restoredHash !== "") {
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${window.location.search}${restoredHash}`,
  );
}

const container = document.getElementById("root");
if (container !== null) {
  createRoot(container).render(
    <StrictMode>
      <I18nProvider>
        <App />
      </I18nProvider>
    </StrictMode>,
  );
}
