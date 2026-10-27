# Homebrew formula

`pgard.rb` is a template for the Homebrew formula of PGARD. It installs the npm registry tarball of the `pgard` package and depends on Homebrew's `node`. The formula lives in a separate **tap** repository, not in this one. This directory only holds the template and a helper script. Nothing here creates the tap or publishes anything.

Users install it after the first release with:

```sh
brew tap jadenmeister/pgard   # once
brew install pgard
```

`brew tap jadenmeister/pgard` adds `JadenMeister/homebrew-pgard`. After that the short name works for install and `brew upgrade pgard`. The one-line form `brew install jadenmeister/pgard/pgard` taps automatically. A bare `brew install pgard` without the tap only works once the formula is in homebrew-core, which requires Homebrew's notability criteria and is not planned for the first release.

## Create the tap repository (once, by the owner)

1. On GitHub create a **public** repository named exactly `homebrew-pgard` under `JadenMeister`. Homebrew maps `jadenmeister/pgard` to `JadenMeister/homebrew-pgard`.
2. Add a `Formula/` directory and copy `pgard.rb` to `Formula/pgard.rb`.
3. Wait until the first version is on npm (see [docs/RELEASING.md](../../docs/RELEASING.md)), then run the update script below so that `url` and `sha256` are real. A formula with the placeholder checksum does not install.
4. Commit and push to the tap's default branch.

## Update the formula for each release

After `npm publish` has finished and `npm view pgard@<version>` shows the version:

```sh
packaging/homebrew/update-formula.sh <version> /path/to/homebrew-pgard/Formula/pgard.rb
```

The script downloads `https://registry.npmjs.org/pgard/-/pgard-<version>.tgz`, compares it with the `dist.integrity` (sha512) that the registry reports, and only then writes the new `url` and its `sha256` into the formula. Without the second argument it edits the template next to it. Then, in the tap repository:

```sh
brew audit --strict --new --online jadenmeister/pgard/pgard   # needs the tap installed locally
brew install --build-from-source jadenmeister/pgard/pgard
brew test jadenmeister/pgard/pgard                            # runs `pgard --version`
git commit -am "pgard <version>" && git push
```

Do these checks before you push if you can: the tap is what users install from. The `test do` block runs `pgard --version` and expects the formula version in its output.

## Notes

- The formula follows the current Homebrew convention for npm formulae: `system "npm", "install", *std_npm_args` and a symlink of the package's `bin` entries into the Homebrew `bin`. `std_npm_args` makes npm install the downloaded tarball into the formula's `libexec`, with `bin` links under `libexec/bin`.
- PGARD has native optional dependencies (`@napi-rs/keyring` ships one prebuilt binary per platform). If `brew audit` or the install complains about binaries for other platforms, follow Homebrew's `node` formula guidance for removing or relinking them in the tap.
- Homebrew runs npm with `--min-release-age=1`: it refuses a package version that was published less than a day ago. If a dependency was published less than a day before the PGARD release, `brew install` fails until that day has passed. Wait a day before updating the tap, and exact-pin and check the dependencies' publish dates when you bump them.
- The `license` is MIT. The version in `url` must match the version the CLI reports, because `test do` compares them.
