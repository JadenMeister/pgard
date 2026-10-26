import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { takeTokenFromLocation } from "./api/client";
import { App } from "./app/App";
import { I18nProvider } from "./i18n/I18nProvider";
import "./styles/tokens.css";
import "./styles/app.css";

takeTokenFromLocation(window.location, window.history);

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
