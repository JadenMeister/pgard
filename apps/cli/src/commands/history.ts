import { err, out, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { safeText } from "../ui/formatters/style.js";

/** `pgard history clear [--all | --repo owner/name]`: deletes stored scan results. */
export async function runHistoryClear(
  context: CommandContext,
  repo: string | null,
): Promise<ExitCode> {
  const store = context.deps.openResultStore(context.io.env);
  if (store === null) {
    err(
      context,
      context.errStyle.red("No app-data directory could be determined; nothing to clear."),
    );
    return EXIT_CODES.internal;
  }
  const outcome = await store.clear(repo === null ? {} : { repoName: repo });
  for (const warning of outcome.warnings) {
    err(context, context.errStyle.yellow(safeText(warning, 200)));
  }
  const scope = repo === null ? "" : ` for ${safeText(repo, 120)}`;
  // A cleared history takes the baseline with it: a baseline is a stored scan, and a leftover
  // one would keep grouping findings after the user asked for everything to be deleted.
  const baselines =
    outcome.baselinesRemoved === 0
      ? ""
      : ` and ${outcome.baselinesRemoved} baseline${outcome.baselinesRemoved === 1 ? "" : "s"}`;
  out(
    context,
    `Deleted ${outcome.removed} stored scan result${outcome.removed === 1 ? "" : "s"}${baselines}${scope} from ${store.dir}.`,
  );
  return outcome.warnings.length > 0 ? EXIT_CODES.partial : EXIT_CODES.ok;
}
