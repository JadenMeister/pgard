# Vendored grammars

Prebuilt tree-sitter grammars for the language track, loaded by `web-tree-sitter` (WASM). They are
vendored unchanged so PGARD needs no native module, no install script and no large grammar bundle.
A test (`src/tree-sitter/grammars.test.ts`) checks every SHA-256 below.

| File                      | Source                                                                      | SHA-256                                                            | License                           |
| ------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------- |
| `tree-sitter-java.wasm`   | `@vscode/tree-sitter-wasm@0.3.1`, `wasm/tree-sitter-java.wasm`              | `4fdeac4ca6ca089f06c6f7e562abcac1733cd465728cc7031ebb73c2019122c4` | MIT, `LICENSE.tree-sitter-java`   |
| `tree-sitter-python.wasm` | `@vscode/tree-sitter-wasm@0.3.1`, `wasm/tree-sitter-python.wasm`            | `16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47` | MIT, `LICENSE.tree-sitter-python` |
| `tree-sitter-php.wasm`    | `@vscode/tree-sitter-wasm@0.3.1`, `wasm/tree-sitter-php.wasm`               | `d4df6a6ff08c87c3ec4f9cbb785fe09998a0cb570e03f57d7b19b3acfb146aa7` | MIT, `LICENSE.tree-sitter-php`    |
| `tree-sitter-kotlin.wasm` | `@tree-sitter-grammars/tree-sitter-kotlin@1.1.0`, `tree-sitter-kotlin.wasm` | `7009d69453bc8735e438b2818a633efb21c88f99782769abba60dffedfab73f7` | MIT, `LICENSE.tree-sitter-kotlin` |

Java, Python and PHP were built by Microsoft's `vscode-tree-sitter-wasm` (tree-sitter-cli 0.25) from
the upstream grammars `tree-sitter-java` 0.23.5, `tree-sitter-python` 0.25.0 and `tree-sitter-php`
0.24.2 (MIT). `LICENSE.vscode-tree-sitter-wasm` is the package's own MIT license.

Kotlin comes from the `@tree-sitter-grammars/tree-sitter-kotlin` tarball. That package declares an
`install` script (`node-gyp-build`) for its native binding, which PGARD does not allow, so only the
`.wasm` file is taken (`npm pack`, then `package/tree-sitter-kotlin.wasm`).

To update a grammar: pack the new version, replace the file, update the checksum here and in the
test, and re-run the tests. Licenses are also listed in the root `NOTICE.md`.
