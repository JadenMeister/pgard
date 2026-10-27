# Changelog

All notable changes to PGARD are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org) with the pre-1.0 policy in [docs/RELEASING.md](docs/RELEASING.md). There is no release yet; everything merged so far is listed under Unreleased.

## [Unreleased]

### Added

- Scanning: `scan code`, `scan history`, `scan web` and `scan all` for the Git root of the current directory, with rules for JavaScript/TypeScript, React, Vue and Go, plus committed `.env` files and secrets in Git history.
- Java and Kotlin SQL injection rule `PG-SQL-005` (JDBC, Spring JdbcTemplate, JPA/Hibernate, Spring Data `@Query` SpEL, MyBatis `${}` in mapper XML and annotations); intra-procedural, SQL injection only.
- Authorization gate: GitHub sign-in stored in the OS keychain, owner approval through the PGARD GitHub App (including a guided install and re-check), organization-owner support and the contribution check.
- Loopback dashboard (English and Korean) and redacted HTML and PDF reports, with an embedded Korean-capable PDF font.
- Output formats: `--format json` (result schema 1.1, `readScanResult`) and `--format sarif` (SARIF 2.1.0); a grouped, severity-sorted terminal result screen.
- Rule metadata: OWASP Top 10 2025, CWE Top 25 and CERT Java mappings, rationale and remediation, rule statistics and a standards coverage map; Korean or English rule text.
- Tree-sitter based analysis foundation, lockfile parsing and a user-run OSV data download (`pgard advisories update`).
- Project configuration file `pgard.config.json`, suppressions and baselines, a local result store with retention and history clearing, and comparison with the previous scan.
- Windows support; an accuracy corpus with precision and recall checked in CI.
- Single installable npm package `pgard` built with `npm run pack:pgard` and checked by `npm run smoke:pack`; release workflow, Homebrew formula template and release procedure (nothing published yet).
- Docs: [TUI approach evaluation](docs/TUI_EVALUATION.md) for the M6 CLI dashboard (no code change).

### Changed

- The result and report text is localized in Korean and English (CLI, reports, dashboard).
- Rule rationale and remediation texts and mappings were rewritten against OWASP 2025 and concrete attack and fix examples.
- Requires Node.js 22.23.4, 24.22.1 or 26.12.1, or a newer patch on the same line; `pgard doctor` fails older releases.
- Analysis is code-based: a scan does not check dependencies against an advisory database. The only OSV use is the user-run `pgard advisories update` download.

### Fixed

- Many false negatives and false positives in secret, auth, cookie and CSRF detection and in Git history checks.
- Port-discovery and dashboard port-gate races, keychain sign-in races, and layout at narrow widths.
- Install guidance for private repositories outside the App installation and for a 404 when the App already covers all repositories.

### Security

- Dashboard and web checks are loopback-only; reports and results are redacted, and the dashboard gates port discovery on the full authorization outcome.
- Packaged grammars are checksum-pinned and verified; the package has no install scripts and only exact-pinned direct dependencies.

[Unreleased]: https://github.com/JadenMeister/pgard/commits/main
