import { useState, type DragEvent, type FormEvent } from "react";
import type { PickerConfirmResponse } from "../../../shared/picker-types";
import { Button } from "../../components/ui/Button";
import { Notice } from "../../components/ui/Notice";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import { CandidateCard, CopyCommand } from "./CandidateCard";
import { usePicker, type PickerControl } from "./use-picker";

export function DropZone({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const [isOver, setIsOver] = useState(false);
  const onDrop = (event: DragEvent<HTMLDivElement>): void => {
    // Never let the browser open the dropped folder; only its name is read (see drop.ts).
    event.preventDefault();
    setIsOver(false);
    control.submitDrop(event.dataTransfer);
  };
  return (
    <div
      className={isOver ? "pick-drop pick-drop-over" : "pick-drop"}
      role="group"
      aria-label={m.picker.dropLabel}
      onDragEnter={(event) => {
        event.preventDefault();
        setIsOver(true);
      }}
      onDragOver={(event) => {
        event.preventDefault();
        setIsOver(true);
      }}
      onDragLeave={() => setIsOver(false)}
      onDrop={onDrop}
    >
      <p className="pick-drop-title">{isOver ? m.picker.dropActive : m.picker.dropTitle}</p>
      <p className="muted small">{m.picker.dropHint}</p>
    </div>
  );
}

export function SearchForm({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const [value, setValue] = useState("");
  const isRunning = control.phase.kind === "running";
  const onSubmit = (event: FormEvent): void => {
    event.preventDefault();
    control.submitTyped(value.trim());
  };
  return (
    <form className="pick-search" onSubmit={onSubmit}>
      <label htmlFor="pick-name" className="pick-search-label">
        {m.picker.searchLabel}
      </label>
      <div className="pick-search-row">
        {/* No autofill, no spell check and no autocapitalize: the name is not kept anywhere. */}
        <input
          id="pick-name"
          className="pick-input"
          type="text"
          value={value}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={255}
          placeholder={m.picker.searchPlaceholder}
          onChange={(event) => setValue(event.target.value)}
        />
        <Button type="submit" variant="primary" disabled={isRunning}>
          {m.picker.searchButton}
        </Button>
      </div>
    </form>
  );
}

export function SearchStatus({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const { phase } = control;
  if (phase.kind !== "running") return null;
  return (
    <p className="pick-status" role="status">
      <span className="pick-spinner" aria-hidden="true" />
      {m.picker.searching(phase.visited)}{" "}
      <Button size="sm" onClick={control.cancelSearch}>
        {m.picker.cancelSearch}
      </Button>
    </p>
  );
}

export function NameProblem({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  if (control.droppedFile) {
    return (
      <Notice tone="warning">
        {m.picker.droppedFile} {m.picker.droppedFileFix}
      </Notice>
    );
  }
  if (control.nameProblem === null) return null;
  return (
    <Notice tone="warning">
      {m.picker.nameProblem} {m.picker.nameReasons[control.nameProblem]} {m.picker.nameExample}
    </Notice>
  );
}

function Results({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const { phase, scope } = control;
  if (phase.kind !== "result") return null;
  const { response, name } = phase;
  const candidates = response.candidates;
  const addCommand = scope?.addCommand ?? null;
  return (
    <Section title={m.picker.results} level={2}>
      {response.status === "partial" && (
        <Notice tone="warning">
          {m.picker.partial(response.stoppedAfterSeconds, response.stoppedBy)} {m.picker.partialFix}
        </Notice>
      )}
      {response.uninspected > 0 && (
        <p className="muted">{m.picker.uninspectedNote(response.uninspected)}</p>
      )}
      {candidates.length === 0 ? (
        <div className="empty-state">
          <p className="empty-state-title">{m.picker.noMatch(name)}</p>
          <p>{m.picker.noMatchFix}</p>
          {addCommand !== null && <CopyCommand text={addCommand} />}
        </div>
      ) : (
        <>
          {candidates.length > 1 && <p className="muted">{m.picker.several}</p>}
          <ul className="pick-list">
            {candidates.map((candidate) => (
              <CandidateCard
                key={candidate.candidateId}
                candidate={candidate}
                addCommand={addCommand}
                onChoose={control.choose}
                onRemoveRecent={null}
              />
            ))}
          </ul>
        </>
      )}
    </Section>
  );
}

function RecentList({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const { recent, scope } = control;
  const addCommand = scope?.addCommand ?? null;
  return (
    <Section title={m.picker.recentTitle} level={2}>
      {recent === null || recent.validating ? (
        <p className="muted" role="status">
          {m.picker.recentValidating}
        </p>
      ) : (
        <>
          {recent.ignored && <Notice tone="warning">{m.picker.recentIgnored}</Notice>}
          {recent.entries.length === 0 ? (
            !recent.ignored && <p className="muted">{m.picker.recentEmpty}</p>
          ) : (
            <ul className="pick-list">
              {recent.entries.map((entry) => (
                <CandidateCard
                  key={entry.entryId}
                  candidate={entry}
                  addCommand={addCommand}
                  onChoose={control.choose}
                  onRemoveRecent={() => control.removeRecent(entry.entryId)}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </Section>
  );
}

function ScopePanel({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const { scope } = control;
  if (scope === null) return null;
  const hasEnabled = scope.roots.some((root) => root.enabled);
  return (
    <Section title={m.picker.searchedRoots} level={2}>
      <ul className="pick-roots">
        {scope.roots.map((root) => (
          <li key={root.id}>
            <label className="pick-root">
              <input
                type="checkbox"
                checked={root.enabled}
                aria-label={m.picker.rootToggle(root.label)}
                onChange={(event) => control.toggleRoot(root.id, event.target.checked)}
              />
              <code>{root.label}</code>
            </label>
          </li>
        ))}
      </ul>
      {!hasEnabled && <p className="muted">{m.picker.noRoots}</p>}
      <p className="muted small">{m.picker.noMatchFix}</p>
      <CopyCommand text={scope.addCommand} />
    </Section>
  );
}

function ConfirmPanel({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  const { candidate } = control;
  if (candidate === null) return null;
  const repo = candidate.remote.status === "github" ? candidate.remote.repo : null;
  return (
    <Section title={m.picker.confirmTitle} level={2}>
      <div className="pick-confirm">
        <p>{m.picker.confirmPath}</p>
        <pre className="pick-confirm-path">{candidate.displayPath}</pre>
        {candidate.collision !== null && (
          <p>
            <span className="badge badge-suspected">
              {m.picker.collisionTag(candidate.collision.tag)}
            </span>
          </p>
        )}
        {repo !== null && (
          <>
            <p className="pick-repo-large">{repo}</p>
            <p className="muted">{m.picker.confirmRemote(repo)}</p>
          </>
        )}
        <p className="muted">{m.picker.confirmNext}</p>
        <p className="pick-actions">
          <Button variant="primary" disabled={control.isConfirming} onClick={control.confirm}>
            {control.isConfirming ? m.picker.confirming : m.picker.confirmButton}
          </Button>
          <Button disabled={control.isConfirming} onClick={control.back}>
            {m.picker.back}
          </Button>
        </p>
      </div>
    </Section>
  );
}

/**
 * The start screen of `pgard web`: a drop zone and a search box (the browser sends only a folder
 * name), the matches with their real path and remote, the recent list and the search folders. A
 * candidate is confirmed on its own screen before anything is checked.
 */
export function PickerView({ control }: { control: PickerControl }) {
  const { m } = useI18n();
  return (
    <div className="picker">
      <h1 className="page-title">{m.picker.title}</h1>
      <p className="muted pick-lead">{m.picker.lead}</p>
      {control.error !== null && <Notice tone="error">{control.error}</Notice>}
      {control.candidate !== null ? (
        <ConfirmPanel control={control} />
      ) : (
        <>
          <DropZone control={control} />
          <SearchForm control={control} />
          <NameProblem control={control} />
          <SearchStatus control={control} />
          <Results control={control} />
          <RecentList control={control} />
          <ScopePanel control={control} />
        </>
      )}
    </div>
  );
}

export function ProjectPicker({
  onConfirmed,
}: {
  onConfirmed: (r: PickerConfirmResponse) => void;
}) {
  return <PickerView control={usePicker(onConfirmed)} />;
}
