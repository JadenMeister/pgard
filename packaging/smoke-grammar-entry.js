// Smoke-test entry (not part of the public API): loads tree-sitter grammars from the installed
// package and scans a temporary project with them, offline.
export { scanSourceCode } from "../packages/source-analysis/dist/scan-source.js";
export { TreeSitterRuntime } from "../packages/source-analysis/dist/tree-sitter/runtime.js";
export {
  GRAMMAR_SHA256,
  TREE_SITTER_LANGUAGES,
  grammarPath,
  readVerifiedGrammar,
} from "../packages/source-analysis/dist/tree-sitter/languages.js";
