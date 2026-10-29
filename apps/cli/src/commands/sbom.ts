import { open, realpath, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import { buildCycloneDxSbom, SBOM_FORMAT } from "@pgard/dependencies";
import { isAuthorizationAllowed, PGARD_VERSION } from "@pgard/scan-core";
import {
  err,
  out,
  promptContextOf,
  suspendKeys,
  throwIfCancelled,
  type CommandContext,
} from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { createSessionProvider } from "../flows/authenticate.js";
import { checkOutputDir } from "../flows/export-report.js";
import { authorizationDepsFor } from "../flows/guided-install.js";
import { promptConfirm } from "../ui/components/prompts.js";
import { formatAuthorization } from "../ui/formatters/result-view.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { NOT_A_REPOSITORY_MESSAGE } from "./project/verify.js";

export interface SbomCommand {
  format: typeof SBOM_FORMAT;
  outputDir: string | null;
  lang?: "en" | "ko";
}

/** `pgard-sbom-<UTC time>-<commit>.cdx.json`: fixed pattern, nothing user-chosen in it. */
export function sbomFileName(timestamp: string, revision: string | null): string {
  const stamp = timestamp.replace(/[^0-9]/g, "").slice(0, 14) || "unknown";
  const commit = (revision ?? "").replace(/[^0-9a-f]/gi, "").slice(0, 8) || "nocommit";
  return `pgard-sbom-${stamp}-${commit}.cdx.json`;
}

class SbomWriteError extends Error {
  readonly code: "file_exists" | "write_failed";
  constructor(code: "file_exists" | "write_failed") {
    super(code);
    this.code = code;
  }
}

/** Exclusive create (`wx`, mode 0600): an existing file or symlink is never overwritten or followed. */
async function writeExclusive(filePath: string, content: string): Promise<void> {
  let handle;
  try {
    handle = await open(filePath, "wx", 0o600);
  } catch (error) {
    throw new SbomWriteError(
      (error as NodeJS.ErrnoException).code === "EEXIST" ? "file_exists" : "write_failed",
    );
  }
  let isWritten = false;
  try {
    await handle.writeFile(content);
    isWritten = true;
  } catch {
    throw new SbomWriteError("write_failed");
  } finally {
    await handle.close().catch(() => undefined);
    if (!isWritten) await unlink(filePath).catch(() => undefined);
  }
}

/**
 * `pgard sbom`: writes a CycloneDX 1.6 JSON SBOM of the dependencies in this repository's
 * lockfiles. It reads local files only: no network (apart from the repository checks below), no
 * package manager or build tool, nothing uploaded.
 *
 * Reading a repository's files is what the authorization gate guards, so the five repository
 * checks run first, exactly as for `pgard report`, and nothing is read unless they allow it. The
 * destination follows the report rules: an explicit existing `--output-dir` (a directory inside
 * the repository needs a yes), or else a fresh private directory (0700); a fixed file name,
 * created with `wx` and mode 0600, never overwritten.
 */
export async function runSbom(context: CommandContext, command: SbomCommand): Promise<ExitCode> {
  const text = cliText(context.ruleLocale);
  const t = text.commands.sbomCommand;
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }

  const confirmInside = async (): Promise<boolean> => {
    err(context, context.errStyle.yellow(t.insideRepositoryWarning));
    const prompts = promptContextOf(context, t.insideRepositoryWarning);
    if (prompts === null) {
      err(context, t.cannotConfirm);
      return false;
    }
    return promptConfirm(prompts, t.confirmInside);
  };

  // A destination problem is an input error: reject it before any network activity.
  let outputDir: string | null = null;
  if (command.outputDir !== null) {
    const check = await checkOutputDir(context, command.outputDir, projectRoot);
    if (check.kind === "invalid") {
      err(context, context.errStyle.red(check.message));
      return EXIT_CODES.usage;
    }
    if (check.isInsideRepository && !(await confirmInside())) return EXIT_CODES.usage;
    outputDir = check.outputDir;
  }

  suspendKeys(context);
  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  const outcome = await context.deps.verifyProject(projectRoot, authorization);
  throwIfCancelled(context);
  if (!isAuthorizationAllowed(outcome) || typeof outcome.repositoryId !== "number") {
    out(context, formatAuthorization(outcome.summary, context.style));
    err(context, context.errStyle.red(t.notVerified));
    return EXIT_CODES.blocked;
  }

  let isPrivateDir = false;
  if (outputDir === null) {
    try {
      outputDir = await context.deps.makeSbomDir();
      isPrivateDir = true;
    } catch {
      err(context, context.errStyle.red(t.cannotCreateDir));
      return EXIT_CODES.partial;
    }
    const check = await checkOutputDir(context, outputDir, projectRoot);
    if (check.kind === "invalid") {
      err(context, context.errStyle.red(check.message));
      return EXIT_CODES.partial;
    }
    outputDir = check.outputDir;
    if (check.isInsideRepository && !(await confirmInside())) {
      await rmdir(outputDir).catch(() => undefined);
      return EXIT_CODES.usage;
    }
  }

  out(context, context.style.dim(t.localNote));
  const collection = await context.deps.collectDependencies(projectRoot);
  throwIfCancelled(context);
  const timestamp = new Date(context.deps.now()).toISOString();
  const bom = buildCycloneDxSbom(collection, {
    serialNumber: context.deps.newSerialNumber(),
    timestamp,
    toolVersion: PGARD_VERSION,
    repository: outcome.repo ?? text.unknown,
    revision: outcome.revision,
  });

  const filePath = path.join(await realpath(outputDir), sbomFileName(timestamp, outcome.revision));
  try {
    await writeExclusive(filePath, `${JSON.stringify(bom, null, 2)}\n`);
  } catch (error) {
    if (isPrivateDir) await rmdir(outputDir).catch(() => undefined);
    const code = error instanceof SbomWriteError ? error.code : null;
    err(
      context,
      context.errStyle.red(
        t.notSaved(
          code === "file_exists"
            ? safeText(`refusing to overwrite ${filePath}`, 500)
            : t.unexpectedWriteError,
        ),
      ),
    );
    if (code === "file_exists") err(context, t.fileExistsHint);
    return EXIT_CODES.partial;
  }
  out(context, t.saved(safeText(filePath, 500), bom.components.length));
  if (bom.components.length === 0) err(context, context.errStyle.yellow(t.noComponents));
  const unparsed = bom.metadata.properties.filter(
    (property) => property.name === "pgard:unparsed-lockfile",
  ).length;
  if (unparsed > 0) err(context, context.errStyle.yellow(t.incomplete(unparsed)));
  if (collection.isTruncated) err(context, context.errStyle.yellow(t.truncated));
  return EXIT_CODES.ok;
}
