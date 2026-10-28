import type { ServiceIdentity } from "@pgard/http-local";
import { promptContextOf, throwIfCancelled, type CommandContext } from "../context.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { BACK, promptChoice, promptConfirm, type Choice } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { looksAutomated } from "./panels.js";

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
}

function describe(identity: ServiceIdentity, processName: string | null): OfferedTarget {
  const url = identity.url.replace(/\/$/, "");
  const detail =
    identity.title !== null
      ? safeText(identity.title, 60)
      : processName !== null
        ? safeText(processName, 30)
        : null;
  return { port: identity.port, label: detail === null ? url : `${url} (${detail})` };
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
): Promise<OfferedTarget[]> {
  const discovery = await withinBudget(context.deps.discoverListeningPorts(), budgetMs, null);
  const ports = discovery?.ports.slice(0, WEB_OFFER_MAX_PROBES) ?? [];
  if (ports.length === 0) return [];
  if (!(await beforeProbe())) return [];
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
            return identity.isHttp ? describe(identity, entry.processName) : null;
          })(),
          budgetMs,
          null,
        ),
      ),
    );
    return described
      .filter((entry): entry is OfferedTarget => entry !== null)
      .slice(0, WEB_OFFER_MAX_TARGETS);
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
  options: { budgetMs?: number; beforeProbe?: () => Promise<boolean> } = {},
): Promise<number | null> {
  const text = cliText(context.ruleLocale).webOffer;
  const prompts = promptContextOf(context, text.help);
  if (prompts === null) return null;
  const targets = await findWebTargets(context, options.budgetMs, options.beforeProbe);
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
