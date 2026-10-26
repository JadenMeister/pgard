import { Card } from "../../components/ui/Card";
import { en } from "../../i18n/en";
import { useI18n } from "../../i18n/I18nProvider";

/** English text (see i18n/en.ts, kept in sync with the README section "Privacy and network traffic"). */
export const LEGAL_POINTS: readonly string[] = en.legal.points;

export function LegalNotice({ onAccept }: { onAccept: () => void }) {
  const { m } = useI18n();
  return (
    <Card title={m.cards.legal}>
      <ul className="legal-list">
        {m.legal.points.map((point) => (
          <li key={point}>{point}</li>
        ))}
      </ul>
      <button type="button" className="button primary" onClick={onAccept}>
        {m.legal.accept}
      </button>
    </Card>
  );
}
