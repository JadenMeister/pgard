// Smoke-test entry (not part of the public API): loads tree-sitter grammars from the installed package.
export { TreeSitterRuntime } from "../packages/source-analysis/dist/tree-sitter/runtime.js";
export {
  GRAMMAR_SHA256,
  TREE_SITTER_LANGUAGES,
  grammarPath,
  readVerifiedGrammar,
} from "../packages/source-analysis/dist/tree-sitter/languages.js";
// The source scanner itself (offline: reads files only), for the installed-tarball PHP smoke.
export { scanSourceCode } from "../packages/source-analysis/dist/index.js";
