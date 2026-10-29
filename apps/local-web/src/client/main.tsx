import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Root } from "./app/Root";
import { prepareAddress } from "./app/startup";
import { installDropGuard } from "./features/picker/drop";
import { I18nProvider } from "./i18n/I18nProvider";
import "./styles/tokens.css";
import "./styles/app.css";
import "./styles/picker.css";
import "./styles/simple.css";

prepareAddress(window);
// A file dropped outside the drop zone would navigate the page away (and show its path).
installDropGuard(window);

const container = document.getElementById("root");
if (container !== null) {
  createRoot(container).render(
    <StrictMode>
      <I18nProvider>
        <Root />
      </I18nProvider>
    </StrictMode>,
  );
}
