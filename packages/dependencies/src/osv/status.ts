import { osvDataDir } from "../app-data.js";
import type { Ecosystem } from "../types.js";
import { filesMatchMeta, readMeta } from "./store.js";
import { OSV_ECOSYSTEMS } from "./update.js";

/** Advisory data older than this is "stale": OSV changes daily and a week is already a long gap. */
export const STALE_AFTER_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

export type AdvisoryState = "none" | "fresh" | "stale" | "damaged";

export interface EcosystemAdvisoryStatus {
  ecosystem: Ecosystem;
  state: AdvisoryState;
  fetchedAt: string | null;
  /** Whole days since `fetchedAt`, or null when there is no data. */
  ageDays: number | null;
  modifiedMax: string | null;
}

export interface AdvisoryStatus {
  /** `none` if any ecosystem has no data; `damaged`, then `stale`, else `fresh`. */
  overall: AdvisoryState;
  ecosystems: EcosystemAdvisoryStatus[];
}

/** Reports how old the downloaded OSV data is. Reads local metadata only; never the network. */
export async function readAdvisoryStatus(
  appDataDir: string,
  now: number = Date.now(),
  staleAfterDays: number = STALE_AFTER_DAYS,
): Promise<AdvisoryStatus> {
  const osvDir = osvDataDir(appDataDir);
  const ecosystems: EcosystemAdvisoryStatus[] = [];
  for (const ecosystem of OSV_ECOSYSTEMS) {
    const meta = await readMeta(osvDir, ecosystem);
    const fetched = meta === null ? Number.NaN : Date.parse(meta.fetchedAt);
    if (meta === null || Number.isNaN(fetched)) {
      ecosystems.push({
        ecosystem,
        state: "none",
        fetchedAt: null,
        ageDays: null,
        modifiedMax: null,
      });
      continue;
    }
    const ageDays = Math.max(0, Math.floor((now - fetched) / DAY_MS));
    const intact = await filesMatchMeta(osvDir, meta);
    ecosystems.push({
      ecosystem,
      state: !intact ? "damaged" : ageDays >= staleAfterDays ? "stale" : "fresh",
      fetchedAt: meta.fetchedAt,
      ageDays,
      modifiedMax: meta.modifiedRange?.max ?? null,
    });
  }
  const states = ecosystems.map((entry) => entry.state);
  const overall: AdvisoryState = states.includes("none")
    ? "none"
    : states.includes("damaged")
      ? "damaged"
      : states.includes("stale")
        ? "stale"
        : "fresh";
  return { overall, ecosystems };
}
