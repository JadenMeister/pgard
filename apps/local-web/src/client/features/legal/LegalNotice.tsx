import { Card } from "../../components/ui/Card";

export const LEGAL_POINTS: readonly string[] = [
  "Scan data is processed once, on this computer. PGARD does not upload source code or results to any server.",
  "PGARD contacts GitHub to sign you in and to read repository metadata (owner approval, your access, merged contributions). Updating advisory data, when you choose to, also uses the network.",
  "Results, the session token and the GitHub sign-in live only in memory and are discarded when you stop the dashboard. Only reports you export remain, and you are responsible for storing and sharing them.",
  "Web checks send anonymous GET requests to the local service you confirm. A badly implemented application can still change state on GET; PGARD does not guarantee that checks have no side effects.",
  "Only scan projects you are authorized to scan. The authorization check runs before every scan and cannot be skipped.",
];

export function LegalNotice({ onAccept }: { onAccept: () => void }) {
  return (
    <Card title="Before you start">
      <ul className="legal-list">
        {LEGAL_POINTS.map((point) => (
          <li key={point}>{point}</li>
        ))}
      </ul>
      <button type="button" className="button primary" onClick={onAccept}>
        I understand
      </button>
    </Card>
  );
}
