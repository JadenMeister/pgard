import { Language, Parser, type Tree } from "web-tree-sitter";
import { grammarPath, type TreeSitterLanguage } from "./languages.js";

export interface ParseLimits {
  /** Source larger than this (UTF-8 bytes) is not parsed. */
  maxBytes: number;
  /** Wall-clock budget for one parse. */
  timeoutMs: number;
}

export const DEFAULT_PARSE_LIMITS: ParseLimits = { maxBytes: 1024 * 1024, timeoutMs: 5000 };

export interface ParseOptions extends Partial<ParseLimits> {
  /** Injectable clock (ms) for tests. */
  now?: () => number;
}

export type ParseOutcome =
  | {
      status: "parsed";
      tree: Tree;
      /** `ERROR` nodes in the tree. A file with syntax errors is still analyzable. */
      errorCount: number;
      /** `MISSING` nodes (tokens the parser inserted to recover). */
      missingCount: number;
      /** Frees the WASM memory of the tree. Call exactly once when done with it. */
      dispose: () => void;
    }
  | { status: "too_large"; bytes: number; maxBytes: number }
  | { status: "timeout"; timeoutMs: number }
  | { status: "failed"; reason: string };

/** Counts `ERROR` and `MISSING` nodes, descending only into subtrees that contain one. */
export function countSyntaxProblems(tree: Tree): { errorCount: number; missingCount: number } {
  let errorCount = 0;
  let missingCount = 0;
  const root = tree.rootNode;
  if (!root.hasError) return { errorCount, missingCount };
  const cursor = tree.walk();
  try {
    let done = false;
    while (!done) {
      const node = cursor.currentNode;
      if (node.isError) errorCount += 1;
      else if (node.isMissing) missingCount += 1;
      if (node.hasError && cursor.gotoFirstChild()) continue;
      while (!cursor.gotoNextSibling()) {
        if (!cursor.gotoParent()) {
          done = true;
          break;
        }
      }
    }
  } finally {
    cursor.delete();
  }
  return { errorCount, missingCount };
}

/**
 * Lazy tree-sitter runtime. The WASM runtime starts on the first parse and each grammar loads on
 * the first file of its language, never earlier: a project without Kotlin never loads Kotlin.
 */
export class TreeSitterRuntime {
  private initPromise: Promise<void> | null = null;
  private readonly languages = new Map<TreeSitterLanguage, Promise<Language>>();
  private readonly parsers = new Map<TreeSitterLanguage, Parser>();
  private readonly loaded = new Set<TreeSitterLanguage>();
  private readonly loadMs = new Map<TreeSitterLanguage, number>();

  /** Languages whose grammar has been loaded so far, in load order. */
  loadedLanguages(): TreeSitterLanguage[] {
    return [...this.loaded];
  }

  /** Whether the WASM runtime has been started. */
  isStarted(): boolean {
    return this.initPromise !== null;
  }

  /** Cold-load time of a loaded grammar in milliseconds. */
  grammarLoadMs(language: TreeSitterLanguage): number | undefined {
    return this.loadMs.get(language);
  }

  private async loadLanguage(language: TreeSitterLanguage): Promise<Language> {
    let pending = this.languages.get(language);
    if (!pending) {
      this.initPromise ??= Parser.init();
      pending = (async () => {
        await this.initPromise;
        const startedAt = performance.now();
        const loaded = await Language.load(grammarPath(language));
        this.loadMs.set(language, performance.now() - startedAt);
        this.loaded.add(language);
        return loaded;
      })();
      this.languages.set(language, pending);
      // A failed load is retried by the next caller instead of poisoning the cache.
      pending.catch(() => this.languages.delete(language));
    }
    return pending;
  }

  /**
   * Parses `source`. Never throws: an oversized file, a timeout and a grammar that fails to load
   * are returned as outcomes, and the caller must report them as partial coverage, never as safe.
   */
  async parse(
    language: TreeSitterLanguage,
    source: string,
    options: ParseOptions = {},
  ): Promise<ParseOutcome> {
    const maxBytes = options.maxBytes ?? DEFAULT_PARSE_LIMITS.maxBytes;
    const timeoutMs = options.timeoutMs ?? DEFAULT_PARSE_LIMITS.timeoutMs;
    const now = options.now ?? (() => performance.now());
    const bytes = Buffer.byteLength(source, "utf8");
    if (bytes > maxBytes) return { status: "too_large", bytes, maxBytes };
    try {
      const grammar = await this.loadLanguage(language);
      let parser = this.parsers.get(language);
      if (!parser) {
        parser = new Parser();
        parser.setLanguage(grammar);
        this.parsers.set(language, parser);
      }
      const startedAt = now();
      const tree = parser.parse(source, null, {
        // Returning true cancels the parse.
        progressCallback: () => now() - startedAt > timeoutMs,
      });
      if (tree === null) {
        parser.reset();
        return { status: "timeout", timeoutMs };
      }
      let counts;
      try {
        counts = countSyntaxProblems(tree);
      } catch (error) {
        tree.delete();
        throw error;
      }
      const { errorCount, missingCount } = counts;
      return { status: "parsed", tree, errorCount, missingCount, dispose: () => tree.delete() };
    } catch (error) {
      return { status: "failed", reason: error instanceof Error ? error.message : String(error) };
    }
  }

  /** Frees parsers and grammars. The runtime can be used again afterwards. */
  dispose(): void {
    for (const parser of this.parsers.values()) parser.delete();
    this.parsers.clear();
    this.languages.clear();
    this.loaded.clear();
  }
}
