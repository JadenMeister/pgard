import type { ProjectSignals, ServiceIdentity } from "@pgard/http-local";
import { promptContextOf, throwIfCancelled, type CommandContext } from "../context.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { BACK, promptChoice, promptConfirm, type Choice } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { looksAutomated } from "./panels.js";
import { judgeService } from "./select-local-port.js";

/** Total time for finding and describing local servers; the scan never waits longer for the offer. */
export const WEB_OFFER_BUDGET_MS = 1200;
/** Listeners probed at most; a developer machine can have many unrelated ones. */
export const WEB_OFFER_MAX_PROBES = 8;
/** Targets listed at most. */
export const WEB_OFFER_MAX_TARGETS = 5;

export interface WebOfferEligibility {
  /** `pgard scan` without a scope word (not `scan code`, `scan web`, ...). */
  isDefaultScope: boolean;
  /** `--port` was given. */
  hasPort: boolean;
  /** `--format json|sarif`. */
  isMachineFormat: boolean;
}

/** The offer is for an interactive terminal only; explicit flags and automation always win. */
export function shouldOfferWebTarget(
  context: CommandContext,
  eligibility: WebOfferEligibility,
): boolean {
  return (
    eligibility.isDefaultScope &&
    !eligibility.hasPort &&
    !eligibility.isMachineFormat &&
    context.keys !== null &&
    context.io.stdout.isTTY === true &&
    !looksAutomated(context.io.env)
  );
}

export interface OfferedTarget {
  port: number;
  label: string;
  /** Looks like this project (title, headers or framework match); listed first. */
  isLikely: boolean;
}

function describe(
  identity: ServiceIdentity,
  processName: string | null,
  project: ProjectSignals | null,
  mark: string,
): OfferedTarget {
  const url = identity.url.replace(/\/$/, "");
  const detail =
    identity.title !== null
      ? safeText(identity.title, 60)
      : processName !== null
        ? safeText(processName, 30)
        : null;
  const isLikely = judgeService(identity, project)?.verdict === "likely";
  const base = detail === null ? url : `${url} (${detail})`;
  return { port: identity.port, label: isLikely ? `${base} ${mark}` : base, isLikely };
}

/** Resolves with `fallback` when `work` is not done in `ms` or fails; never rejects. */
async function withinBudget<T>(work: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms);
    timer.unref?.();
  });
  try {
    return await Promise.race([work.catch(() => fallback), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Finds local HTTP services within the time budget. Never throws and never waits past the
 * budget: a failed or slow discovery gives an empty list. `beforeProbe` runs only when
 * something listens, and must say whether probing is allowed (the authorization gate). Its
 * time does not count: discovery and the probes each get the full budget. Each probe is judged
 * on its own, so a port that answers in time is kept even when another one hangs; at the end
 * (or on cancel) the remaining probes are aborted.
 */
export async function findWebTargets(
  context: CommandContext,
  budgetMs: number = WEB_OFFER_BUDGET_MS,
  beforeProbe: () => Promise<boolean> = async () => true,
  getProject: () => Promise<ProjectSignals | null> = async () => null,
): Promise<OfferedTarget[]> {
  const discovery = await withinBudget(context.deps.discoverListeningPorts(), budgetMs, null);
  const ports = discovery?.ports.slice(0, WEB_OFFER_MAX_PROBES) ?? [];
  if (ports.length === 0) return [];
  if (!(await beforeProbe())) return [];
  if (context.signal.aborted) return [];
  const mark = cliText(context.ruleLocale).webRelated.likelyMark;
  // Local files only; a failure just means no judgement.
  const project = await withinBudget(
    getProject().catch(() => null),
    budgetMs,
    null,
  );
  if (context.signal.aborted) return [];
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  context.signal.addEventListener("abort", abort, { once: true });
  try {
    const described = await Promise.all(
      ports.map((entry) =>
        withinBudget(
          (async (): Promise<OfferedTarget | null> => {
            const identity = await context.deps.probeLocalService(entry.port, {
              timeoutMs: budgetMs,
              signal: controller.signal,
            });
            return identity.isHttp ? describe(identity, entry.processName, project, mark) : null;
          })(),
          budgetMs,
          null,
        ),
      ),
    );
    const found = described.filter((entry): entry is OfferedTarget => entry !== null);
    // The ones that look like this project first; ties keep the discovery order.
    const ordered = [
      ...found.filter((entry) => entry.isLikely),
      ...found.filter((entry) => !entry.isLikely),
    ];
    const shown = ordered.slice(0, WEB_OFFER_MAX_TARGETS);
    // Within the cap, the list always keeps one server the heuristic did not pick.
    const other = ordered.find((entry) => !entry.isLikely);
    if (
      other !== undefined &&
      shown.length === WEB_OFFER_MAX_TARGETS &&
      shown.every((entry) => entry.isLikely)
    ) {
      shown[WEB_OFFER_MAX_TARGETS - 1] = other;
    }
    return shown;
  } finally {
    controller.abort();
    context.signal.removeEventListener("abort", abort);
  }
}

/**
 * Asks whether to also scan one of the detected local servers. Returns the chosen port, or
 * `null` for no (the default, Esc, Ctrl+C, nothing found). The port still goes through
 * `selectLocalPort`, exactly like `--port`, so nothing here confirms a target.
 */
export async function offerWebTarget(
  context: CommandContext,
  options: {
    budgetMs?: number;
    beforeProbe?: () => Promise<boolean>;
    getProject?: () => Promise<ProjectSignals | null>;
  } = {},
): Promise<number | null> {
  const text = cliText(context.ruleLocale).webOffer;
  const prompts = promptContextOf(context, text.help);
  if (prompts === null) return null;
  const targets = await findWebTargets(
    context,
    options.budgetMs,
    options.beforeProbe,
    options.getProject,
  );
  // A cancel confirmed while looking (Ctrl+C in the menu) takes effect before any question.
  throwIfCancelled(context);
  const only = targets[0];
  if (only === undefined) return null;
  // Esc and Enter are no; a confirmed Ctrl+C throws UserCancelledError and cancels the scan.
  if (targets.length === 1) {
    return (await promptConfirm(prompts, text.askOne(only.label))) ? only.port : null;
  }
  const choices: Choice<number | null>[] = [
    { label: text.none, value: null },
    ...targets.map((target) => ({ label: target.label, value: target.port })),
  ];
  const picked = await promptChoice(prompts, text.pickTitle, choices);
  return picked === BACK ? null : picked;
}
