import { useCallback, useEffect, useRef, useState } from "react";
import type {
  PickerCandidate,
  PickerConfirmResponse,
  PickerRecentResponse,
  PickerScopeResponse,
  PickerSearchResponse,
} from "../../../shared/picker-types";
import { checkFolderName, type BadNameReason } from "../../../shared/folder-name";
import { apiGet, apiPost, getProjectEpoch } from "../../api/client";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";
import { readDroppedFolder, type DataTransferLike } from "./drop";
import { pickerErrorText } from "./error-text";

export type SearchPhase =
  | { kind: "idle" }
  | { kind: "running"; searchId: string; name: string; visited: number }
  | { kind: "result"; name: string; response: PickerSearchResponse }
  | { kind: "stopped"; name: string };

export interface PickerControl {
  scope: PickerScopeResponse | null;
  recent: PickerRecentResponse | null;
  phase: SearchPhase;
  /** A problem with the typed or dropped name, found in the page or reported by the server. */
  nameProblem: BadNameReason | null;
  droppedFile: boolean;
  error: string | null;
  candidate: PickerCandidate | null;
  isConfirming: boolean;
  submitTyped: (name: string) => void;
  submitDrop: (dataTransfer: DataTransferLike | null) => void;
  cancelSearch: () => void;
  choose: (candidate: PickerCandidate) => void;
  back: () => void;
  confirm: () => void;
  removeRecent: (entryId: string) => void;
  toggleRoot: (rootId: string, enabled: boolean) => void;
}

/**
 * The picker's state: scope, recent list, one search at a time (polled, cancellable), the
 * candidate being confirmed. The browser only ever sends a folder name and ids the server gave.
 */
export function usePicker(onConfirmed: (response: PickerConfirmResponse) => void): PickerControl {
  const { m } = useI18n();
  const [scope, setScope] = useState<PickerScopeResponse | null>(null);
  const [recent, setRecent] = useState<PickerRecentResponse | null>(null);
  const [phase, setPhase] = useState<SearchPhase>({ kind: "idle" });
  const [nameProblem, setNameProblem] = useState<BadNameReason | null>(null);
  const [droppedFile, setDroppedFile] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [candidate, setCandidate] = useState<PickerCandidate | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);
  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const fail = useCallback(
    (caught: unknown): void => {
      if (isMounted.current) setError(pickerErrorText(m, caught));
    },
    [m],
  );

  useEffect(() => {
    void apiGet<PickerScopeResponse>("/api/picker/scope")
      .then((next) => isMounted.current && setScope(next))
      .catch(fail);
    void apiGet<PickerRecentResponse>("/api/picker/recent")
      .then((next) => isMounted.current && setRecent(next))
      .catch(fail);
  }, [fail]);

  // The recent list is revalidated by the server in the background: poll until it is done.
  usePolling(
    async () => setRecent(await apiGet<PickerRecentResponse>("/api/picker/recent")),
    1000,
    recent?.validating === true,
  );

  usePolling(
    async () => {
      if (phase.kind !== "running") return;
      const response = await apiGet<PickerSearchResponse>(
        `/api/picker/search?id=${encodeURIComponent(phase.searchId)}`,
      );
      if (response.status === "running") {
        setPhase({ ...phase, visited: response.visited });
      } else if (response.status === "cancelled") {
        setPhase({ kind: "stopped", name: phase.name });
      } else if (response.status === "failed") {
        setPhase({ kind: "stopped", name: phase.name });
        setError(m.picker.errors.generic);
      } else {
        setPhase({ kind: "result", name: phase.name, response });
      }
    },
    500,
    phase.kind === "running",
  );

  const start = useCallback(
    (source: "drop" | "typed", raw: string): void => {
      setError(null);
      setDroppedFile(false);
      const checked = checkFolderName(raw, source);
      if (!checked.ok) {
        setNameProblem(checked.reason);
        return;
      }
      setNameProblem(null);
      setCandidate(null);
      apiPost<{ searchId: string }>("/api/picker/search", {
        source,
        name: checked.name,
        epoch: getProjectEpoch(),
      })
        .then((started) => {
          if (isMounted.current) {
            setPhase({
              kind: "running",
              searchId: started.searchId,
              name: checked.name,
              visited: 0,
            });
          }
        })
        .catch(fail);
    },
    [fail],
  );

  const submitDrop = useCallback(
    (dataTransfer: DataTransferLike | null): void => {
      const dropped = readDroppedFolder(dataTransfer);
      if (dropped.kind === "file") {
        setDroppedFile(true);
        setNameProblem(null);
        setError(null);
      } else if (dropped.kind === "none") {
        setDroppedFile(false);
        setNameProblem(null);
        setError(m.picker.droppedNothing);
      } else start("drop", dropped.name);
    },
    [m, start],
  );

  const cancelSearch = useCallback((): void => {
    if (phase.kind !== "running") return;
    const { searchId, name } = phase;
    setPhase({ kind: "stopped", name });
    void apiPost("/api/picker/search/cancel", { searchId }).catch(fail);
  }, [fail, phase]);

  const confirm = useCallback((): void => {
    if (candidate === null || isConfirming) return;
    setError(null);
    setIsConfirming(true);
    apiPost<PickerConfirmResponse>("/api/picker/confirm", {
      candidateId: candidate.candidateId,
      shown: candidate.shown,
      epoch: getProjectEpoch(),
    })
      .then((response) => {
        if (!isMounted.current) return;
        setIsConfirming(false);
        onConfirmed(response);
      })
      .catch((caught: unknown) => {
        if (!isMounted.current) return;
        setIsConfirming(false);
        setCandidate(null);
        setPhase({ kind: "idle" });
        fail(caught);
      });
  }, [candidate, fail, isConfirming, onConfirmed]);

  return {
    scope,
    recent,
    phase,
    nameProblem,
    droppedFile,
    error,
    candidate,
    isConfirming,
    submitTyped: (name) => start("typed", name.trim()),
    submitDrop,
    cancelSearch,
    choose: (next) => {
      setError(null);
      setCandidate(next);
    },
    back: () => {
      setError(null);
      setCandidate(null);
    },
    confirm,
    removeRecent: (entryId) => {
      void apiPost<{ entries: PickerRecentResponse["entries"] }>("/api/picker/recent/remove", {
        entryId,
      })
        .then((next) =>
          setRecent((current) => (current === null ? null : { ...current, entries: next.entries })),
        )
        .catch(fail);
    },
    toggleRoot: (rootId, enabled) => {
      void apiPost<PickerScopeResponse>("/api/picker/scope/toggle", { rootId, enabled })
        .then(setScope)
        .catch(fail);
    },
  };
}
