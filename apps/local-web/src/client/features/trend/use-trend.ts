import { useCallback, useEffect, useState } from "react";
import type { TrendResponse } from "../../../shared/api-types";
import { apiGet } from "../../api/client";

export type TrendState =
  { status: "loading" } | { status: "failed" } | { status: "loaded"; data: TrendResponse };

/**
 * Reads `GET /api/trend` when the Trend view opens, and again on `reload`. The answer belongs to
 * the project the page was opened for: in picker mode a project change remounts the whole app
 * (see `Root`), which drops this state, and the server refuses (`409 project_changed`) an answer
 * that was read for another project. A late answer after unmount is ignored.
 */
export function useTrend(): [TrendState, () => void] {
  const [state, setState] = useState<TrendState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let isCurrent = true;
    setState({ status: "loading" });
    apiGet<TrendResponse>("/api/trend")
      .then((data) => {
        if (isCurrent) setState({ status: "loaded", data });
      })
      .catch(() => {
        if (isCurrent) setState({ status: "failed" });
      });
    return () => {
      isCurrent = false;
    };
  }, [attempt]);
  const reload = useCallback(() => setAttempt((count) => count + 1), []);
  return [state, reload];
}
