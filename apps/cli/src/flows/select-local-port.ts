import type { ConfirmedWebTarget } from "@pgard/findings";
import {
  createConfirmedWebTarget,
  InvalidTargetError,
  parsePort,
  relatedness,
  type ProjectSignals,
  type Relatedness,
  type ServiceIdentity,
} from "@pgard/http-local";
import { out, promptContextOf, type CommandContext } from "../context.js";
import {
  BACK,
  promptChoice,
  promptConfirm,
  promptText,
  type Back,
  type Choice,
} from "../ui/components/prompts.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { safeText } from "../ui/formatters/style.js";

export const PORT_HELP = `Choose the local HTTP service of this project.
- The list shows ports that answered HTTP on 127.0.0.1; it can be incomplete.
- "Other port" lets you type any port from 1 to 65535.
- You confirm the service with y after seeing its URL, status and title.
  The answer is your choice of target, not proof that it belongs to the project.`;

export type PortSelection =
  | { kind: "confirmed"; target: ConfirmedWebTarget }
  /** The user chose to continue without web checks (web is recorded as not tested). */
  | { kind: "skipped" }
  | { kind: "back" };

type PortChoice = { kind: "port"; port: number } | { kind: "other" } | { kind: "skip" };

export function formatServiceIdentity(identity: ServiceIdentity): string {
  const lines = [`  URL:    ${identity.url}`];
  if (!identity.isHttp) {
    lines.push(`  Status: no HTTP response (${safeText(identity.error ?? "unknown error", 120)})`);
    return lines.join("\n");
  }
  lines.push(`  Status: ${identity.status ?? "unknown"}`);
  lines.push(`  Title:  ${identity.title === null ? "(none)" : safeText(identity.title, 200)}`);
  lines.push(
    `  Technology (inferred, not verified): ${
      identity.inferredTechnologies.length === 0
        ? "unknown"
        : identity.inferredTechnologies.map((hint) => safeText(hint, 60)).join(", ")
    }`,
  );
  if (identity.redirectStop !== null) {
    lines.push("  Note:   / redirects to a location PGARD will not follow.");
  }
  return lines.join("\n");
}

/** How the service compares with the project; `unclear` when the project is not known. */
export function judgeService(
  identity: ServiceIdentity,
  project: ProjectSignals | null,
): Relatedness | null {
  if (project === null || !identity.isHttp) return null;
  return relatedness(
    { title: identity.title, technologies: identity.inferredTechnologies },
    project,
  );
}

async function listCandidates(
  context: CommandContext,
  project: ProjectSignals | null,
): Promise<{ choices: Choice<PortChoice>[]; note: string | null }> {
  const mark = cliText(context.ruleLocale).webRelated.likelyMark;
  const discovery = await context.deps.discoverListeningPorts();
  const identities = await Promise.all(
    discovery.ports.map(async (entry) => ({
      entry,
      identity: await context.deps.probeLocalService(entry.port),
    })),
  );
  const listed = identities
    .filter(({ identity }) => identity.isHttp)
    .map(({ entry, identity }) => {
      const isLikely = judgeService(identity, project)?.verdict === "likely";
      return {
        isLikely,
        choice: {
          label: `http://127.0.0.1:${entry.port}`,
          hint: [
            String(identity.status ?? ""),
            identity.title === null ? "" : safeText(identity.title, 60),
            entry.processName === null ? "" : `(${safeText(entry.processName, 30)})`,
            isLikely ? mark : "",
          ]
            .filter((part) => part !== "")
            .join("  "),
          value: { kind: "port", port: entry.port } as PortChoice,
        },
      };
    });
  // The ones that look like this project first; otherwise the discovery order is kept.
  const choices: Choice<PortChoice>[] = [
    ...listed.filter((entry) => entry.isLikely),
    ...listed.filter((entry) => !entry.isLikely),
  ].map((entry) => entry.choice);
  choices.push({ label: "Other port...", value: { kind: "other" } });
  choices.push({
    label: "Continue without web checks",
    hint: "web: not tested",
    value: { kind: "skip" },
  });
  return { choices, note: discovery.note };
}

/**
 * Port selection and explicit confirmation. A preset port (`--port`) still requires the identity
 * check and `y`. Requires an interactive terminal.
 */
export async function selectLocalPort(
  context: CommandContext,
  presetPort: number | null,
  project: ProjectSignals | null = null,
): Promise<PortSelection> {
  const prompts = promptContextOf(context, PORT_HELP);
  if (prompts === null) return { kind: "skipped" };
  let pendingPort = presetPort;
  for (;;) {
    let port: number;
    if (pendingPort !== null) {
      port = pendingPort;
      pendingPort = null;
    } else {
      out(context, context.style.dim("Looking for local HTTP services on 127.0.0.1..."));
      const { choices, note } = await listCandidates(context, project);
      if (note !== null) out(context, context.style.dim(note));
      const picked: PortChoice | Back = await promptChoice(
        prompts,
        "Select the project's local service",
        choices,
      );
      if (picked === BACK) return { kind: "back" };
      if (picked.kind === "skip") return { kind: "skipped" };
      if (picked.kind === "other") {
        const typed = await promptText(prompts, "Port (1-65535):", 5);
        if (typed === BACK) continue;
        try {
          port = parsePort(typed.trim());
        } catch (error) {
          if (error instanceof InvalidTargetError) {
            out(context, context.style.red(safeText(error.message, 120)));
            continue;
          }
          throw error;
        }
      } else {
        port = picked.port;
      }
    }
    const identity = await context.deps.probeLocalService(port);
    out(context, formatServiceIdentity(identity));
    if (!identity.isHttp) {
      out(context, context.style.yellow("This port did not answer HTTP. Choose another port."));
      continue;
    }
    // A hint only: the default stays N and y still works.
    const judged = judgeService(identity, project);
    if (judged?.verdict === "unlikely" && judged.serviceLabel !== null) {
      out(
        context,
        context.style.yellow(
          cliText(context.ruleLocale).webRelated.unlikely(
            safeText(judged.serviceLabel, 40),
            safeText(judged.projectLabel ?? "", 40),
          ),
        ),
      );
    }
    const isConfirmed = await promptConfirm(
      prompts,
      cliText(context.ruleLocale).webRelated.confirm,
    );
    if (isConfirmed) {
      return { kind: "confirmed", target: createConfirmedWebTarget(identity, true) };
    }
    out(
      context,
      context.style.dim("Not confirmed. Choose another port or continue without web checks."),
    );
  }
}
