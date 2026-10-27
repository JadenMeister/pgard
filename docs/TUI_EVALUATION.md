# TUI approach for the M6 CLI dashboard

Evaluation for issue #284. Nothing here ships: no runtime dependency is added and the spikes live outside the repository. Measured on macOS, Node v26.12.1, npm registry state of 2026-10-27, in a temporary `HOME` and `XDG_DATA_HOME`. A "measured" label means a number or behaviour I observed; "inferred" means read from documentation, `engines` fields or issue trackers.

## Recommendation

**Extend the current hand-rolled renderer for M6; do not add Ink or a blessed-style library now.** The dashboard is read-only and made of lists, bars and a few panels, which the existing primitives already draw. A one-panel spike on them took about 77 lines and passed every behaviour check below with zero new dependencies. Ink works well but adds +24 MB and +41 packages to the installed `pgard` and about 90 ms of startup, and it ignores `NO_COLOR` and has its own Ctrl+C semantics, so we would rewrite the conventions we already have. blessed-style options are either unmaintained (neo-blessed, blessed) or large and imperative (terminal-kit). Keep Ink as the fallback if M6-2 hits a wall (see "Revisit if").

## What the CLI has today

`apps/cli/src/ui/` is about 4,800 lines including tests:

- `components/prompts.ts`: arrow-key lists. Enter selects, Esc goes back, `?` shows help, Ctrl+C asks `Cancel and exit? [y/N]` and cancelling exits 130.
- `adapters/terminal.ts`: a raw-mode `KeyReader` (readline keypress events, type-ahead discard) that tests replace with fakes.
- `formatters/style.ts`: `shouldUseColor` (TTY, `NO_COLOR`, `TERM=dumb`), `terminalWidth` (stream, then `COLUMNS`, then 80), `isUnicodeTerminal` (legacy Windows consoles fall back to ASCII), `safeText`.
- `formatters/charts.ts`: bar charts that become `#` bars without colour and plain count lines under 60 columns.
- `i18n/display-width.ts`: CJK-aware width, pad, truncate and wrap.
- `app.ts`: interactive only when stdin and stdout are TTYs; everything else prints the plain result screen or JSON/SARIF. Formatters are pure functions with snapshot tests (`result-screen.test.ts`).

The package is built by `scripts/pack-pgard.mjs`: workspace packages are bundled by esbuild, every third-party package stays an external pinned dependency. Today: 2.70 MB packed, 11.8 MB unpacked, 27 files; installed with its 42 npm packages it is 76.9 MB on disk. PGARD itself requires Node `^22.23.4 || ^24.22.1 || >=26.12.1`, so Node 20 is already out of scope for any candidate.

## Criteria and measurements

| Criterion                             | Current renderer                                     | Ink 8.0.0 (+ react)                                                                                                                   | neo-blessed 0.2.0                                            | terminal-kit 3.1.4                                      |
| ------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------- |
| Added packages (measured)             | 0                                                    | +41 (83 vs 42 installed)                                                                                                              | +1                                                           | +19                                                     |
| Added disk, installed (measured)      | 0                                                    | +24.2 MB (`es-toolkit` alone 18 MB)                                                                                                   | +1.8 MB                                                      | +8.1 MB                                                 |
| Licences (measured)                   | MIT (ours)                                           | MIT x37, ISC, MIT-or-CC0                                                                                                              | MIT                                                          | MIT x16, BSD-3, BSD-3-and-Apache-2.0, one with no field |
| `npm audit` (measured)                | n/a                                                  | 0 advisories                                                                                                                          | 0 advisories                                                 | 0 advisories                                            |
| Last release (measured)               | n/a                                                  | repo pushed 2026-10-26, npm modified 2026-10-03                                                                                       | npm 2022-05-10, repo last pushed 2021-04                     | npm 2026-07-19                                          |
| Node support (inferred, `engines`)    | same as PGARD                                        | `>=22`, fits PGARD; no Node 20                                                                                                        | `>=8`                                                        | `>=16.13`                                               |
| Startup cost, median of 25 (measured) | 0 (baseline `node -e 0` 68 ms)                       | +88 ms (156 ms to import `ink` and `react`)                                                                                           | +11 ms                                                       | +10 ms                                                  |
| Spike size                            | 77 lines                                             | 64 lines                                                                                                                              | 75 lines                                                     | not built                                               |
| `NO_COLOR` (measured)                 | honoured (`#` bars, no SGR colour)                   | **ignored**: colour codes still emitted; `FORCE_COLOR=0` and `TERM=dumb` work. Must gate every colour prop ourselves                  | honoured only because the spike checks it itself             | not tested                                              |
| Ctrl+C                                | confirm `y/N`, exit 130                              | exits 0 immediately by default (`exitOnCtrlC`); confirm needs custom code                                                             | spike's own binding exited 0                                 | not tested                                              |
| Non-TTY (measured)                    | plain text, as today                                 | crashes when stdin is not a TTY ("Raw mode is not supported"); app must gate                                                          | would write control codes; app must gate (inferred)          | not tested                                              |
| Snapshot testing (measured)           | pure `frame()` to lines, same style as today's tests | `renderToString` gives a plain-text frame (colour stripped when piped); key handling needs a pty or `ink-testing-library` (not tried) | `screen.screenshot()` on fake streams works, 0 bytes written | not tested                                              |
| Alternate screen (measured)           | 2 escape codes written by us, restored on exit       | opt-in `alternateScreen`, enter/leave and cursor restore seen                                                                         | default, restored on exit                                    | not tested                                              |

## Spike findings

Each spike showed a severity summary plus a scrollable findings list from a real `ScanResult` JSON: 36 findings (1 critical, 17 high, 14 medium, 4 low), produced by the real CLI pipeline (`pgard scan code`, mock GitHub) on a temporary Git repository seeded with the accuracy-corpus positive samples. The Current spike imports the CLI's own built modules (`createKeyReader`, `createStyle`, `renderChart`, `truncateWidth`). Spikes ran in a pseudo-terminal with a screen emulator (pyte), so what I saw is emulator output, not a real terminal.

Verified for all three spikes: arrows scroll; `?` toggles help; Esc quits (or closes help first); Ctrl+C quits; resize from 24x80 to 14x50 redraws with the narrow layout; `NO_COLOR` gives `#` bars (Ink only after we gate colour ourselves); at 60 and 40 columns the list truncates and under 60 the bars become counts; a Korean title column keeps its right border aligned; cursor and alternate screen are restored on exit. Tab and Enter were exercised in the Ink and blessed spikes only (Tab moved a focus flag); the Current spike does not bind them, which is trivial because `KeyReader` already reports `tab` and `return`.

What differed:

- **Ink.** Declarative and pleasant, correct CJK width and resize without effort. Costs: 88 ms and 24 MB; `NO_COLOR` is not read; interactive mode needs a TTY stdin and fails hard otherwise; Ctrl+C and Esc semantics are ours to re-create. Version 8 requires Node 22+ and React as a second runtime dependency to keep audited. Without `alternateScreen`, output taller than the screen is a documented pain point in its tracker (flicker and scrollback erasure issues, now closed).
- **neo-blessed.** Smallest and fastest, but the package has had no release since 2022 and the repo no push since 2021; the original `blessed` has 254 open issues and its last push was 2024-03. Wide characters need `fullUnicode: true`. Its border drawing uses terminal line-drawing (ACS) characters, which the emulator rendered as `lqqk`; I assume a real terminal draws lines, but legacy Windows consoles are a known risk. Not recommended.
- **Current renderer.** Everything the spike needed already existed. The missing pieces are small: a frame function, a resize handler, alternate-screen enter/leave with cleanup on every exit path, and Page/Home/End keys.

Not tested: terminal-kit (not built into a spike; its tracker lists "Cannot open /dev/tty on Windows" and a wanted-maintainers call), `ink-testing-library`, Node 22 or 24 (only Node 26 is installed here), and any real terminal emulator.

## Windows

**Nothing about Windows was observed.** All runs were on macOS. From documentation and trackers (inferred): Ink's CI workflow appears to run on Linux only and I found no Windows-specific claim in its docs; terminal-kit has open Windows issues (above); blessed-style libraries rely on terminfo and ACS characters, which legacy conhost handles poorly. The existing CLI already treats conhost as ASCII-only through `isUnicodeTerminal`,. Before M6 closes, run the panel once on `windows-latest` (render-and-exit check) and by hand in Windows Terminal, PowerShell and conhost, covering resize flicker, Korean width and the alternate screen.

## Trade-offs

| Choose           | You gain                                                                                                       | You pay                                                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Current renderer | No new supply chain, 0 ms, `NO_COLOR`/`COLUMNS`/CJK/ASCII fallbacks and Ctrl+C reused, snapshot tests as today | We write layout, scrolling, filter input and redraw logic; each new panel is hand-laid-out; no focus system                                  |
| Ink              | Declarative components, flexbox layout, focus helpers, a `renderToString` test path                            | +24 MB, +41 packages, +88 ms (avoidable for other commands by lazy `import`), React in a security tool, own colour/Ctrl+C handling, TTY-only |
| blessed-style    | Widgets (lists, boxes, forms) out of the box                                                                   | Unmaintained (neo-blessed, blessed) or heavy and imperative (terminal-kit); weaker Windows story                                             |

## What M6-2 would need

1. A `ui/dashboard/` module: `state` and `reduce(state, key)` as pure code, and `renderFrame(state, size, style)` returning lines. Panels: summary and charts (reuse `renderChart`), coverage, findings list with a detail view, filter, trend, export action.
2. A small screen controller: enter and leave the alternate screen and hide and restore the cursor on every exit path (normal, Ctrl+C, thrown error, `SIGTERM`), redraw on `resize`, no output when not a TTY.
3. `KeyReader` extensions: Page Up/Down, Home/End, `/` for a one-line filter input, plus a decision on Esc latency (readline waits to disambiguate escape sequences; I did not measure it).
4. Reuse the Ctrl+C confirm and exit 130, `?` help, Esc back, `shouldUseColor`, `terminalWidth`, `isUnicodeTerminal`, `safeText` and the 60-column narrow layout; `NO_COLOR` and a non-TTY keep the current text result screen.
5. Tests: reducer tests, frame snapshots at 40, 60 and 80 columns in English and Korean, and a fake-`CliIo` key script, matching `result-screen.test.ts`.
6. Windows checks as above. Read-only over a completed `ScanResult`, no network access, results stay local.

## Revisit if

Move to Ink (lazy-imported from the dashboard command only, pinned, with `exitOnCtrlC: false` and our own `NO_COLOR` gate) if M6-2 needs more than about three interacting focusable panes, multi-line text input, or if the hand-written redraw logic passes roughly 400 lines. That decision needs owner approval of the +24 MB and the new dependency review, as the issue states.
