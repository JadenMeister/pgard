import type { ServiceIdentity } from "@pgard/http-local";
import { out, promptContextOf, type CommandContext } from "../context.js";
import { cliText } from "../ui/i18n/cli-text.js";
import {
  BACK,
  promptChoice,
  promptConfirm,
  UserCancelledError,
  type Choice,
} from "../ui/components/prompts.js";
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
 * something listens, and must say whether probing is allowed (the authorization gate); the
 * time it takes does not count against the budget.
 */
export async function findWebTargets(
  context: CommandContext,
  budgetMs: number = WEB_OFFER_BUDGET_MS,
  beforeProbe: () => Promise<boolean> = async () => true,
): Promise<OfferedTarget[]> {
  const startedAt = Date.now();
  const discovery = await withinBudget(context.deps.discoverListeningPorts(), budgetMs, null);
  const ports = discovery?.ports.slice(0, WEB_OFFER_MAX_PROBES) ?? [];
  if (ports.length === 0) return [];
  if (!(await beforeProbe())) return [];
  const remaining = Math.max(budgetMs - (Date.now() - startedAt), Math.min(400, budgetMs));
  const described = await withinBudget(
    Promise.all(
      ports.map(async (entry) => {
        try {
          const identity = await context.deps.probeLocalService(entry.port);
          return identity.isHttp ? describe(identity, entry.processName) : null;
        } catch {
          return null;
        }
      }),
    ),
    remaining,
    [] as (OfferedTarget | null)[],
  );
  return described
    .filter((entry): entry is OfferedTarget => entry !== null)
    .slice(0, WEB_OFFER_MAX_TARGETS);
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
  const only = targets[0];
  if (only === undefined) return null;
  try {
    if (targets.length === 1) {
      return (await promptConfirm(prompts, text.askOne(only.label))) ? only.port : null;
    }
    const choices: Choice<number | null>[] = [
      { label: text.none, value: null },
      ...targets.map((target) => ({ label: target.label, value: target.port })),
    ];
    const picked = await promptChoice(prompts, text.pickTitle, choices);
    return picked === BACK ? null : picked;
  } catch (error) {
    // Ctrl+C at this optional question means no; the scan itself goes on without web checks.
    if (error instanceof UserCancelledError) {
      out(context, "");
      return null;
    }
    throw error;
  }
}
