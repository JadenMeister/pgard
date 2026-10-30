import type { ConnectOutcome } from "../api/client";
import { LanguageToggle, useI18n } from "../i18n/I18nProvider";
import type { Messages } from "../i18n/types";

export type NoticeOutcome = Exclude<ConnectOutcome, "connected">;

/** The heading and the plain sentences for a page that could not connect (#419). */
export function connectionText(
  m: Messages,
  outcome: NoticeOutcome,
): { title: string; lines: string[] } {
  const c = m.connection;
  switch (outcome) {
    case "used":
      return { title: c.usedTitle, lines: [c.used, c.usedNotYou] };
    case "expired":
      return { title: c.expiredTitle, lines: [c.expired] };
    case "ended":
      return { title: c.endedTitle, lines: [c.ended] };
    case "no_link":
      return { title: c.noLinkTitle, lines: [c.noLink] };
    case "invalid":
      return { title: c.invalidTitle, lines: [c.invalid] };
    case "unreachable":
      return { title: c.unreachableTitle, lines: [c.unreachable] };
  }
}

/**
 * A whole page instead of the app when this tab has no session: a reused link (another tab, a
 * copied link, the history), an expired link, an ended session. Plain text, no raw error code.
 */
export function ConnectionNotice({ outcome }: { outcome: NoticeOutcome }) {
  const { m, language } = useI18n();
  const text = connectionText(m, outcome);
  return (
    <>
      <header className="topbar">
        <div className="wrap topbar-in">
          <p className="brand">
            <span className="brand-name">pgard</span>
          </p>
          <LanguageToggle />
        </div>
      </header>
      <main id="main" className="wrap main simple" lang={language}>
        <h1 className="page-title">{text.title}</h1>
        {text.lines.map((line) => (
          <p key={line} className="simple-lead">
            {line}
          </p>
        ))}
      </main>
    </>
  );
}
