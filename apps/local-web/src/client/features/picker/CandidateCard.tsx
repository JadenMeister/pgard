import { useState } from "react";
import type { PickerCandidate } from "../../../shared/picker-types";
import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";

/** A copy button for a command: the text goes to the clipboard, never anywhere else. */
export function CopyCommand({ text }: { text: string }) {
  const { m } = useI18n();
  const [isCopied, setIsCopied] = useState(false);
  return (
    <span className="pick-command">
      <code className="pick-code">{text}</code>
      <Button
        size="sm"
        onClick={() => {
          void navigator.clipboard
            ?.writeText(text)
            .then(() => setIsCopied(true))
            .catch(() => undefined);
        }}
      >
        {isCopied ? m.picker.copied : m.picker.copy}
      </Button>
    </span>
  );
}

/** What happened, why and what to do for a candidate that cannot be selected. */
export function BlockedNote({
  candidate,
  addCommand,
  onRemoveRecent,
}: {
  candidate: PickerCandidate;
  addCommand: string | null;
  onRemoveRecent: (() => void) | null;
}) {
  const { m } = useI18n();
  const { blocked } = candidate;
  if (blocked === null) return null;
  const text = m.picker.blocked[blocked.code];
  return (
    <div className="pick-blocked" role="note">
      <p className="pick-blocked-title">{m.picker.blockedTitle}</p>
      <p>
        <strong>{m.picker.whyLabel}:</strong> {text.reason}
      </p>
      <p>
        <strong>{m.picker.fixLabel}:</strong> {text.fix}
      </p>
      {blocked.code === "group_or_world_writable" && blocked.paths.length > 0 && (
        <>
          <p className="muted small">{m.picker.failingPaths}</p>
          <ul className="pick-paths">
            {blocked.paths.map((path) => (
              <li key={path}>
                <code>{path}</code>
              </li>
            ))}
          </ul>
          <CopyCommand text={blocked.fix} />
        </>
      )}
      {blocked.code === "outside_scope" && addCommand !== null && (
        <p>
          <CopyCommand text={addCommand} />
        </p>
      )}
      {onRemoveRecent !== null && (
        <p>
          <Button
            size="sm"
            aria-label={m.picker.recentRemoveLabel(candidate.name)}
            onClick={onRemoveRecent}
          >
            {m.picker.recentRemove}
          </Button>
        </p>
      )}
    </div>
  );
}

/** The path, the repository and the source of one candidate: text only, never HTML. */
export function CandidateDetails({ candidate }: { candidate: PickerCandidate }) {
  const { m } = useI18n();
  return (
    <>
      <p className="pick-path" data-testid="candidate-path">
        <span className="sr-only">{m.picker.pathLabel}: </span>
        {candidate.displayPath}
      </p>
      {candidate.displayPathEscaped !== null && (
        <p className="pick-path pick-path-escaped">
          <span className="muted small">{m.picker.escapedPathLabel}</span>
          <br />
          {candidate.displayPathEscaped}
        </p>
      )}
      {/* An unreadable or ambiguous remote is explained by the blocked note, not repeated here. */}
      {(candidate.remote.status === "github" ||
        candidate.remote.status === "none" ||
        candidate.remote.status === "not_github") && (
        <p className="small">
          <span className="muted">{m.picker.remoteLabel}: </span>
          {candidate.remote.status === "github" ? (
            <span className="pick-repo">{candidate.remote.repo}</span>
          ) : (
            <span className="muted">{m.picker.noRemote}</span>
          )}
        </p>
      )}
    </>
  );
}

/** One candidate or recent entry as a card: choose it, or read why it cannot be chosen. */
export function CandidateCard({
  candidate,
  addCommand,
  onChoose,
  onRemoveRecent,
}: {
  candidate: PickerCandidate;
  addCommand: string | null;
  onChoose: (candidate: PickerCandidate) => void;
  onRemoveRecent: (() => void) | null;
}) {
  const { m } = useI18n();
  return (
    <li className={candidate.blocked === null ? "pick-card" : "pick-card pick-card-blocked"}>
      <div className="pick-card-head">
        <strong className="pick-name">{candidate.name}</strong>
        <span className="badge">
          {candidate.source === "recent" ? m.picker.sourceRecent : m.picker.sourceScope}
        </span>
        {candidate.collision !== null && (
          <span className="badge badge-suspected">
            {m.picker.collisionTag(candidate.collision.tag)}
          </span>
        )}
      </div>
      <CandidateDetails candidate={candidate} />
      {candidate.blocked === null ? (
        <p>
          <Button variant="primary" size="sm" onClick={() => onChoose(candidate)}>
            {m.picker.choose}
          </Button>
        </p>
      ) : (
        <BlockedNote
          candidate={candidate}
          addCommand={addCommand}
          onRemoveRecent={onRemoveRecent}
        />
      )}
    </li>
  );
}
