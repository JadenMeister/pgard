# Vendored grammars

`tree-sitter-kotlin.wasm` is the prebuilt Kotlin grammar shipped in the npm package
`@tree-sitter-grammars/tree-sitter-kotlin@1.1.0` (MIT, license in `LICENSE.tree-sitter-kotlin`;
source: https://github.com/tree-sitter-grammars/tree-sitter-kotlin).

SHA-256: `7009d69453bc8735e438b2818a633efb21c88f99782769abba60dffedfab73f7`

Why vendored: that package declares an `install` script (`node-gyp-build`) for its native binding,
and PGARD allows no install scripts and no native modules. The `.wasm` file is extracted unchanged
from the published tarball (`npm pack`, then `package/tree-sitter-kotlin.wasm`). The Java, Python
and PHP grammars come from the `@vscode/tree-sitter-wasm` dependency instead.

To update: pack the new version, replace the file and this checksum, and re-run the tests.
