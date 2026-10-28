import { OSV_EXPORT_HOST } from "@pgard/dependencies";
import { err, out, throwIfCancelled, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";

const MIB = 1024 * 1024;
const formatMiB = (bytes: number): string => `${(bytes / MIB).toFixed(1)} MiB`;
const formatSeconds = (ms: number): string => `${(ms / 1000).toFixed(1)} s`;

/**
 * `pgard advisories update`: the only command that downloads advisory data. It is user-run, talks
 * to the OSV export host only, sends no package names, and keeps the old data on any failure.
 */
export async function runAdvisoriesUpdate(
  context: CommandContext,
  force = false,
): Promise<ExitCode> {
  const { deps, style } = context;
  const appDataDir = deps.appDataDir;
  if (appDataDir === null) {
    err(
      context,
      "No home directory was found, so PGARD has nowhere to store advisory data. Nothing was downloaded. Set HOME (or XDG_DATA_HOME / LOCALAPPDATA) to an absolute path and try again.",
    );
    return EXIT_CODES.partial;
  }
  out(
    context,
    `Downloading public OSV data from ${OSV_EXPORT_HOST} (nothing is uploaded; no package names are sent).`,
  );
  let lastReported = -1;
  const outcomes = await deps.updateAdvisories({
    appDataDir,
    signal: context.signal,
    now: deps.now,
    ...(force ? { force: true } : {}),
    onProgress: (ecosystem, received, total) => {
      if (total === null || !context.io.stderr.isTTY) return;
      const percent = Math.floor((received / total) * 10) * 10;
      if (percent !== lastReported && percent < 100) {
        lastReported = percent;
        err(context, style.dim(`  ${ecosystem}: ${percent}% of ${formatMiB(total)}`));
      }
    },
  });
  throwIfCancelled(context);
  let failed = 0;
  for (const outcome of outcomes) {
    if (!outcome.ok) {
      failed += 1;
      out(
        context,
        `  ${style.red("[fail]")} ${outcome.ecosystem}: ${outcome.error} The previous data (if any) is unchanged.`,
      );
      if (outcome.refusal !== undefined) {
        out(
          context,
          `    This protects you from a stale or replayed download. If you are sure the new data is what you want, run \`pgard advisories update --force\`.`,
        );
      }
      continue;
    }
    const { meta } = outcome;
    const range =
      meta.modifiedRange === null
        ? ""
        : `, records modified ${meta.modifiedRange.min.slice(0, 10)} to ${meta.modifiedRange.max.slice(0, 10)}`;
    out(
      context,
      `  ${style.green("[ok]  ")} ${outcome.ecosystem}: ${meta.counts.advisories} advisories + ${meta.counts.malware} malware (MAL-) records${range}; downloaded ${formatMiB(meta.archive.bytes)} in ${formatSeconds(outcome.downloadMs)}, indexed in ${formatSeconds(outcome.indexMs)}; sha256 ${meta.archive.sha256.slice(0, 16)}...`,
    );
  }
  out(
    context,
    failed === 0
      ? style.green("Advisory data is up to date on this computer.")
      : style.yellow(`${failed} ecosystem(s) failed; see [fail] above.`),
  );
  return failed === 0 ? EXIT_CODES.ok : EXIT_CODES.partial;
}
