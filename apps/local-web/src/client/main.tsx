import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { takeTokenFromLocation } from "./api/client";
import { App } from "./app/App";
import "./styles/tokens.css";
import "./styles/app.css";

takeTokenFromLocation(window.location, window.history);

const container = document.getElementById("root");
if (container !== null) {
  createRoot(container).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
