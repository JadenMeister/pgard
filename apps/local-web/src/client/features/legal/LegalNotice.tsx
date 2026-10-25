import { Card } from "../../components/ui/Card";

/** Keep in sync with the README section "Privacy and network traffic". */
export const LEGAL_POINTS: readonly string[] = [
  "Scan data is processed once, on this computer. PGARD does not upload source code or results to any server.",
  "The only external network traffic is to GitHub: the device-flow sign-in on github.com (and refreshing a saved sign-in there) and GitHub API calls that read what authorization needs (your identity, the app installation, your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub. The pgard doctor command also checks whether api.github.com is reachable.",
  "After authorization passes, PGARD sends one GET / to each discovered listening port on 127.0.0.1 to show its identity.",
  "PGARD does not ship, download or query a vulnerability database. Findings come from the code itself (query statements, server code, configuration), Git history and the local HTTP checks you select.",
  "The GitHub sign-in is saved in the OS keychain (macOS Keychain, Windows Credential Manager or the Linux Secret Service), never in a file, so the CLI and the dashboard can reuse it. It stays in the local PGARD process and is never sent to the browser. Without a keychain it is kept in memory only. Use pgard logout, or the dashboard's sign-out that removes it from the keychain, to delete it.",
  "Results and the dashboard session token live only in memory and are discarded when you stop the dashboard. Only reports you export remain, and you are responsible for storing and sharing them.",
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
