import { err, out, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { safeText } from "../ui/formatters/style.js";

/** `pgard history clear [--all | --repo owner/name]`: deletes stored scan results. */
export async function runHistoryClear(
  context: CommandContext,
  repo: string | null,
): Promise<ExitCode> {
  const store = context.deps.resultStore;
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
  out(
    context,
    `Deleted ${outcome.removed} stored scan result${outcome.removed === 1 ? "" : "s"}${scope} from ${store.dir}.`,
  );
  return outcome.warnings.length > 0 ? EXIT_CODES.partial : EXIT_CODES.ok;
}
