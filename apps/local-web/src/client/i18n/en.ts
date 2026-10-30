import { pickerEn } from "./picker-en";

/**
 * English message catalog and the source of truth for the key set: `ko.ts` is typed as
 * `Messages` (derived from this object), so a missing or extra key there is a typecheck error.
 * Keep it free of imports and of component structure so a redesign can reuse it.
 * Parameterized strings are functions. Text that comes from the server or the rules (finding
 * titles, authorization reasons, progress messages) is not part of the catalog.
 */
export const en = {
  language: {
    label: "Language",
    ko: "한국어",
    en: "English",
  },
  picker: pickerEn,
  common: {
    requestFailed: "Request failed.",
    none: "(none)",
    unknown: "unknown",
    all: "All",
  },
  app: {
    subtitle: (version: string | null): string =>
      `Local security dashboard${version === null ? "" : ` - v${version}`}`,
    title: "Security dashboard",
    lead: "Check authorization, choose what to scan and review the findings. Everything runs on this computer.",
    skipToContent: "Skip to content",
    footer: (command: string) =>
      `Runs on 127.0.0.1 only · results are not saved and are gone when you stop ${command}.`,
    errorSession:
      "This session has ended. Start PGARD again in your terminal and open the new URL it prints.",
    errorRuleTexts:
      "Could not load the Korean rule texts. Rule titles and fix texts stay in English; reload the page to try again.",
  },
  connection: {
    title: "PGARD",
    connecting: "Connecting to PGARD on this computer…",
    usedTitle: "This link was already used",
    used: "Each link opens one tab. Use the tab where PGARD is already open, or run pgard web again (pgard dashboard if you started the dashboard) to get a new link.",
    usedNotYou: "If you did not open it, stop the server (Ctrl+C) and run the command again.",
    expiredTitle: "This link expired",
    expired:
      "A link works for 10 minutes until it is first opened. Run the command again to get a new one.",
    endedTitle: "This page's session ended",
    ended:
      "It was idle for 30 minutes, or PGARD was stopped. Run the command again to get a new link.",
    noLinkTitle: "Open PGARD from your terminal",
    noLink:
      "Run pgard web (or pgard dashboard) in your terminal. It opens this page for you; with --print-url it prints the link instead.",
    invalidTitle: "This link is not for this server",
    invalid: "Run the command again to get a new link.",
    unreachableTitle: "PGARD is not reachable",
    unreachable: "Check that the command is still running in your terminal, then reload this page.",
  },
  cards: {
    legal: "Before you start",
    authorization: "Authorization",
    target: "Local web service (optional)",
    scan: "Scan",
    results: "Results",
    standards: "Standards coverage (OWASP Top 10 2025)",
    ruleStats: "Rule statistics",
    report: "Export report",
  },
  legal: {
    // Keep in sync with the README section "Privacy and network traffic".
    points: [
      "Scan data is processed once, on this computer. PGARD does not upload source code or results to any server.",
      "PGARD talks to GitHub: the device-flow sign-in on github.com (and refreshing a saved sign-in there) and GitHub API calls on api.github.com that read what authorization needs (the owner/name of the repository's GitHub remote, your identity, the app installation, your organization membership, your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub. The pgard doctor command also checks whether api.github.com is reachable.",
      "The only other external destination is osv-vulnerabilities.storage.googleapis.com, and only when you run pgard advisories update in a terminal: it downloads public OSV vulnerability data over https and uploads nothing (no package names, no lockfile contents, no GitHub sign-in). The download is verified (zip structure, per-record checksums, size and time limits) and stored in your user data folder under advisories/osv; its integrity rests on https to that pinned host. Scans, SBOM generation and this dashboard never start that download and never send your code, lockfiles or results anywhere.",
      "After authorization passes, PGARD sends one GET / to each discovered listening port on 127.0.0.1 to show its identity.",
      "PGARD does not ship a vulnerability database and a scan never downloads or queries one. Findings come from the code itself (query statements, server code, configuration), Git history, if selected local HTTP checks and, for npm and Go lockfiles, a version match against the OSV data you downloaded with pgard advisories update (not proof that the vulnerable code is reachable or exploitable).",
      "The GitHub sign-in is saved in the OS keychain (macOS Keychain, Windows Credential Manager or the Linux Secret Service), never in a file, so the CLI and the dashboard can reuse it. It stays in the local PGARD process and is never sent to the browser. Without a keychain it is kept in memory only. Use pgard logout, or the dashboard's sign-out that removes it from the keychain, to delete it.",
      "Results of scans you run in the dashboard and the dashboard session token live only in memory and are discarded when you stop the dashboard. Only reports you export remain, and you are responsible for storing and sharing them. Scans run with the pgard command are different: their redacted results are kept in this computer's app-data folder (last 20 scans per repository, 90 days, never uploaded; on macOS and Linux readable only by you) unless you pass --no-store or set PGARD_NO_STORE=1. Delete them with pgard history clear --all.",
      "Web checks send anonymous GET requests to the local service you confirm. A badly implemented application can still change state on GET; PGARD does not guarantee that checks have no side effects.",
      "Only scan projects you are authorized to scan. The authorization check runs before every scan and cannot be skipped.",
    ],
    accept: "I understand",
  },
  auth: {
    projectLabel: "Project",
    intro:
      "PGARD checks owner approval, your current access and a merged contribution before every scan.",
    checks: {
      repository: "Repository",
      github_identity: "GitHub identity",
      owner_approval: "Owner approval",
      current_access: "Current access",
      contribution: "Merged contribution",
    },
    columns: { check: "Check", status: "Status", reason: "Reason" },
    checking: "Checking...",
    allowed: "Allowed",
    blocked: "Blocked - no analysis will run",
    notStored: "This result is not stored; every scan checks again.",
    expiresAt: (time: string): string =>
      `Local service discovery and probes stay open until ${time}; check again after that.`,
    verify: "Verify project",
    recheck: "Check again",
    signOut: {
      sessionOnlyLabel: "End dashboard session (keep keychain sign-in)",
      removeStoredLabel: "Sign out and remove from OS keychain",
      sessionOnlyHint:
        "Forgets the GitHub session in this dashboard only. The sign-in saved in the OS keychain stays, and the next check reuses it without a code.",
      removeStoredHint:
        "Also deletes the saved sign-in from the OS keychain, for the CLI too. The next check asks for a new device code.",
    },
    githubAppEnv: (clientId: string): string =>
      `GitHub App: ${clientId} from PGARD_GITHUB_APP_CLIENT_ID (override of the built-in PGARD App).`,
    githubAppInvalid: (message: string): string =>
      `${message} Until then GitHub identity is unverifiable and every scan is blocked.`,
    storedSignIn: (login: string): string =>
      `GitHub sign-in: ${login}, saved in the OS keychain and reused for each check. The token stays on this computer and is never sent to the browser.`,
    noSignIn:
      "GitHub sign-in: none saved. The next check asks for a device code and saves the sign-in in the OS keychain.",
    keychainUnavailable: (reason: string): string =>
      `GitHub sign-in: the OS keychain is unavailable (${reason}), so the sign-in is kept in memory until the dashboard stops.`,
  },
  status: {
    passed: "passed",
    failed: "failed",
    unverifiable: "unverifiable",
    completed: "Completed",
    partial: "Partial",
    not_tested: "Not tested",
    not_selected: "Not selected",
    blocked: "blocked",
    confirmed: "confirmed",
    suspected: "suspected",
    informational: "informational",
    unknownStatus: "Unknown",
  },
  install: {
    button: "Install the PGARD GitHub App",
    waiting:
      "Waiting for the PGARD GitHub App to be installed... PGARD checks every 5 seconds and runs the full authorization again once it is installed.",
    timedOut:
      "Stopped waiting for the PGARD GitHub App installation after 10 minutes. Install it, then check again.",
    noLink: "No install link is available.",
    askOwner: (account: string): string =>
      `Ask an owner of ${account} to install the PGARD GitHub App:`,
    maybeOwner: (account: string, url: string): string =>
      `If you are an owner of ${account}, install the App on the install page; otherwise ask an owner to install it there: ${url}`,
    owner: (account: string): string =>
      `Owner approval: install the PGARD GitHub App on ${account}. On GitHub, choose "Only select repositories" (this repository) or "All repositories", then click Install. Installing the App is the owner approval; PGARD cannot install it for you.`,
    thisRepository: "this repository",
    // The repository is hidden but the App already covers all repositories of the owner account.
    allRepositoriesNote: (target: string): string =>
      `GitHub shows no access to ${target}. The PGARD GitHub App is already installed on the owner account for all repositories, so adding the repository will not help: your account probably has no access, the repository does not exist, or the git remote is wrong.`,
    // The repository is hidden (GitHub answered 404) and the App is not installed on the owner.
    accessLead:
      "GitHub shows no access to this repository. If it is private, the PGARD GitHub App must be installed for it; PGARD cannot tell this from missing account access.",
    accessPage: (target: string): string =>
      `The page pre-selects "All repositories"; to limit PGARD to this repository, choose "Only select repositories" and pick ${target}, then click Install.`,
    // The repository is hidden and the App is already installed on the owner account.
    repoAccessButton: "Open the App's repository access",
    repoAccessWaiting:
      "Waiting for the repository to be added to the PGARD GitHub App's repository access... PGARD checks every 5 seconds and runs the full authorization again once it is added.",
    repoAccessTimedOut:
      "Stopped waiting for the repository to be added to the PGARD GitHub App's repository access after 10 minutes. Add it, then check again.",
    repoAccessAskOwner: (account: string, target: string): string =>
      `Ask an owner of ${account} to add ${target} to the PGARD GitHub App's repository access:`,
    repoAccessLead: (account: string, target: string): string =>
      `GitHub shows no access to ${target}. The PGARD GitHub App is already installed on ${account}, but its repository access does not include this repository (or your account has no access to it).`,
    repoAccessOwner: (target: string): string =>
      `Owner approval: add ${target} to the PGARD GitHub App's repository access.`,
    repoAccessMaybeOwner: (account: string, target: string, url: string): string =>
      `If you are an owner of ${account}, add ${target} to the PGARD GitHub App's repository access on its settings page; otherwise ask an owner to do it there: ${url}`,
    repoAccessSteps: (target: string): string =>
      `On GitHub, under "Repository access", choose "Only select repositories", add ${target}, then click Save. Changing the App's repository access is the owner approval; PGARD cannot change it for you.`,
  },
  deviceCode: {
    required: "GitHub sign-in is required. Open",
    enterCode: "and enter this code:",
    openButton: "Open the GitHub sign-in page",
    expiry: (minutes: number): string => `Expires in about ${minutes} min.`,
  },
  target: {
    confirmedTarget: "Confirmed target:",
    chooseAnother: "Choose another service",
    intro:
      "Pick the project's service on 127.0.0.1. The list can be incomplete; you can always enter a port. The port number alone says nothing about which project it belongs to.",
    noServices: (note: string | null): string =>
      `No local HTTP services found${note === null ? "" : ` (${note})`}.`,
    otherPort: "Other port",
    check: "Check",
    refresh: "Refresh list",
    identityLabel: "Service identity",
    url: "URL",
    status: "Status",
    noHttp: (error: string): string => `No HTTP response (${error})`,
    title: "Title",
    technology: "Technology (inferred, not verified)",
    redirect: "/ redirects to a location PGARD will not follow.",
    question: "Is this the current project's service?",
    unrelated: (service: string, project: string) =>
      `This service doesn't look related to this project (service: '${service}', project: '${project}').`,
    looksRelated: "(looks like this project)",
    yes: "Yes, this is the project's service",
    no: "No",
    notHttp: "This port did not answer HTTP. Choose another port.",
    access: {
      expired:
        "Port access has expired: PGARD contacts local services only within 30 minutes of a passing authorization check. Use Check again above to continue.",
      running:
        "Waiting for the authorization check. PGARD does not contact local services until it passes.",
      blocked:
        "Authorization was blocked, so PGARD will not discover or probe local services. See the reasons above.",
      failed:
        "The authorization check did not complete, so PGARD will not contact local services. Check again above.",
      idle: "Verify the project above first. PGARD discovers and probes local services only after authorization passes.",
    },
  },
  scan: {
    advisory: {
      label: "Advisory data (OSV)",
      missing:
        "missing. Dependency checks are reported as not tested until you run `pgard advisories update` in a terminal (it downloads public OSV data and uploads nothing).",
      state: {
        fresh: "present, up to date",
        stale: "present, stale",
        damaged: "present, damaged",
        partial: "partial: at least one ecosystem has no data",
      },
      unreadable:
        "could not be read. Run `pgard advisories update` to replace it (it downloads public OSV data and uploads nothing).",
      staleHint: (days: number): string =>
        `Data counts as stale when the download or its newest record is ${days} or more days old; refresh it with \`pgard advisories update\` (the dashboard never downloads it).`,
      damagedHint: "Replace it with `pgard advisories update`.",
      ecosystem: (
        name: string,
        date: string | null,
        days: number | null,
        newest: string | null,
        version: string | null,
      ): string =>
        date === null
          ? `${name}: none`
          : `${name}: downloaded ${date}${days === null ? "" : ` (${days} ${days === 1 ? "day" : "days"} old)`}${newest === null ? "" : `, newest record ${newest}`}${version === null ? "" : `, data version ${version}`}`,
      store: (path: string): string => `Stored in ${path}.`,
      storeElsewhere:
        "The folder is outside your home directory, so its path is hidden; the README lists where each system keeps it.",
    },
    scope: "Scope",
    scopes: {
      code: { label: "Code", hint: "current code and configuration" },
      history: {
        label: "Git history",
        hint: "tracked files and past commits (secrets, risky files)",
      },
      web: { label: "Local web service", hint: "anonymous GET checks of the confirmed target" },
    },
    noWebTarget:
      "No confirmed web target: the web scope will be recorded as not tested and the scan will be partial.",
    configNotice: {
      excluded: (detail: string): string => detail,
      config: (detail: string): string => detail,
      test: (detail: string): string => detail,
      demoted: (count: number): string =>
        `${count} finding${count === 1 ? " was" : "s were"} classified as test code by the testDirectories setting of pgard.config.json (listed apart, confidence capped at low). Review ${count === 1 ? "it" : "them"}.`,
    },
    suppressionNotice: {
      severe: (count: number, high: number, critical: number): string =>
        `${count} suppressed finding${count === 1 ? " is" : "s are"} high or critical (${high} high, ${critical} critical). ${count === 1 ? "It is" : "They are"} still listed under "Suppressed"; check the reason in pgard.config.json.`,
      total: (count: number): string =>
        `${count} findings are suppressed in total (more than 10), however many entries do it.`,
      far: (ruleId: string, path: string, expires: string): string =>
        `The suppression of ${ruleId} for ${JSON.stringify(path)} runs until ${expires}, more than a year ahead. Suppressions should be reviewed regularly.`,
      wildcard: (ruleId: string, path: string, count: number): string =>
        `The suppression of ${ruleId} uses ${JSON.stringify(path)}, which matches every file and every finding of that rule (${count} suppressed).`,
      broad: (ruleId: string, path: string, count: number): string =>
        `The suppression of ${ruleId} for ${JSON.stringify(path)} matches ${count} findings.`,
      expired: (ruleId: string, path: string, expires: string): string =>
        `The suppression of ${ruleId} for ${JSON.stringify(path)} expired on ${expires} and is not applied.`,
      incomplete:
        "Suppression matching stopped early (pattern work limit). Findings checked after that are NOT suppressed and are listed normally.",
      everything: (count: number): string =>
        `Every finding of this scan (${count}) is suppressed by pgard.config.json. They are all listed under "Suppressed"; review the reasons before relying on this result.`,
    },
    baselineNotice: {
      uncertain: (count: number): string =>
        `${count} new finding${count === 1 ? "" : "s"} sit in areas the baseline did not fully cover, so ${count === 1 ? "it" : "they"} may be old.`,
      tool: "PGARD was updated since the baseline was set; rules may have changed, so read the new and in-baseline counts with care.",
    },
    run: "Run scan",
    cancel: "Cancel",
    progress: {
      title: "Scanning",
      stoppedTitle: "Scan stopped",
      elapsed: (time: string): string => `Elapsed ${time}`,
      areasLabel: "Scan progress by area",
      authorization: "Authorization",
      states: {
        waiting: "Waiting",
        running: "Running",
        done: "Done",
        failed: "Failed",
        skipped: "Skipped",
        stopped: "Stopped",
      },
      pages: (count: number): string => `${count} page${count === 1 ? "" : "s"} checked`,
      announce: (area: string, state: string): string => `${area}: ${state}`,
      note: "Each area reports when it starts and when it finishes; PGARD does not estimate how much is left.",
      log: "Activity log",
    },
  },
  coverage: {
    caption: "Coverage",
    area: "Area",
    status: "Status",
    note: "Note",
  },
  severity: {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
  },
  severityInline: {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "info",
  },
  confidence: {
    low: "low",
    medium: "medium",
    high: "high",
  },
  findings: {
    overall: {
      completed: "Completed",
      partial: "Partial - some requested areas did not fully run",
      blocked: "Blocked by the authorization gate - no analysis ran",
      failed: "Failed - an internal error stopped the scan",
      unknown: "Unknown",
    },
    blockedNote: "See the authorization reasons above.",
    headline: (
      overall: string,
      total: number,
      confirmed: number,
      suspected: number,
      informational: number,
      contextNote: string,
    ): string =>
      `${overall} - ${total} finding(s): ${confirmed} confirmed, ${suspected} suspected, ${informational} informational${contextNote === "" ? "" : ` - ${contextNote}`}`,
    filters: "Filters",
    statusOptions: {
      confirmed: "Confirmed",
      suspected: "Suspected",
      informational: "Informational",
    },
    severity: "Severity",
    status: "Status",
    source: "Source",
    search: "Search",
    sources: { code: "Code", history: "History", web: "Web" },
    confidence: (value: string): string => `confidence ${value}`,
    confidenceLabel: "Confidence",
    evidence: "Evidence (redacted)",
    impact: "Impact",
    recommendation: "Recommendation",
    noMatch: "No findings match the filters.",
    noFindings: (outside: string, suppressed: number, breakdown: string): string =>
      `No ${suppressed > 0 ? "unsuppressed " : ""}findings${outside} in the areas that ran${suppressed > 0 ? ` (${suppressed} suppressed${breakdown === "" ? "" : `: ${breakdown}`})` : ""}. This does not mean the project is secure; check coverage.`,
    outsideTestAndVendored: " outside test, fixture or vendored code",
    outsideTest: " outside test or fixture code",
    outsideVendored: " outside vendored code",
    testTitle: (count: number): string => `In test or fixture code (${count})`,
    testAria: "Findings in test or fixture code",
    testNote:
      "Matches in files classified as test or fixture code by their path only, with confidence capped at low. They are not counted above, but review them: a real value committed in a test is still exposed.",
    testNoteConfig: (count: number): string =>
      ` ${count} of them ${count === 1 ? "was" : "were"} classified by the testDirectories setting of pgard.config.json, not by the built-in rules.`,
    vendoredTitle: (count: number): string =>
      `Suggestions: in third-party/vendored code (${count})`,
    vendoredAria: "Suggestions in third-party or vendored code",
    vendoredIntro:
      "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git (",
    vendoredThen: ", then add the directory to ",
    vendoredEnd: ").",
    vendoredNote:
      "Classified by path only: files under a node_modules/, bower_components/, jspm_packages/ or Pods/ directory, or under a vendor/ or third_party/ directory that is not inside src/, app/ or lib/. Confidence is capped at low and they are not counted above, but they are not dropped: a real secret committed there is still exposed.",
    contextTest: (count: number): string => `${count} in test or fixture code`,
    vendoredSuggestions: (count: number, severe: string): string =>
      `${count} suggestion${count === 1 ? "" : "s"} in vendored code${severe === "" ? "" : ` (${severe})`}`,
    plus: (parts: string): string => `plus ${parts}`,
    suppressedCount: (count: number, breakdown: string): string =>
      `${count} suppressed${breakdown === "" ? "" : ` (${breakdown})`}`,
    baselineCount: (matched: number, fresh: number, breakdown: string): string =>
      `baseline: ${matched} in baseline${breakdown === "" ? "" : ` (${breakdown})`}, ${fresh} new`,
    baselineInBaseline: (count: number): string => `${count} in baseline`,
    suppressedTitle: (count: number): string => `Suppressed (${count})`,
    suppressedAria: "Suppressed findings",
    suppressedNote:
      "These findings matched a suppression in pgard.config.json, a file of the scanned repository. They are still reported here and in the JSON result; the reasons are the file's own words, not PGARD's. A section with a critical finding is open.",
    suppressedReason: (reason: string, expires: string): string =>
      `Suppressed by pgard.config.json: ${JSON.stringify(reason)}${expires === "" ? "" : ` (expires ${expires})`}`,
    baselineTitle: (count: number): string => `In baseline (${count})`,
    baselineAria: "Findings in the baseline",
    baselineNote:
      "These findings were already in the baseline (pgard baseline). They are not new, but they are still reported.",
    newBadge: "NEW",
    suppressedMarker: (expires: string): string =>
      expires === "" ? "Suppressed" : `Suppressed until ${expires}`,
    pager: {
      showing: (start: number, end: number, total: number): string =>
        `Showing ${start}–${end} of ${total}`,
      label: (list: string): string => `Pages: ${list}`,
      previous: "Previous",
      next: "Next",
      page: (page: number): string => `Page ${page}`,
      pageSize: "Per page",
      regular: "Findings",
    },
    noDatabase:
      "PGARD does not ship a vulnerability database and a scan never downloads or queries one. Findings come from the code itself (query statements, server code, configuration), Git history, if selected local HTTP checks and, for npm and Go lockfiles, a version match against the OSV data you downloaded with pgard advisories update (not proof that the vulnerable code is reachable or exploitable).",
    location: {
      unknownUrl: "(unknown URL)",
      unknownCommit: "unknown commit",
      commit: (sha: string): string => `commit ${sha}`,
      unknownLocation: "(unknown location)",
    },
  },
  details: {
    standards: "Standards",
    viaCwe: (cwe: string): string => `indirect, via ${cwe}`,
    certDirect: "direct, Java/Kotlin",
    certNone: "SEI CERT Java: no direct rule",
    examples: (count: number): string => `Examples (${count})`,
    vulnerable: "Vulnerable",
    safe: "Safe",
    ruleRationale: "Why the rule matters",
    ruleRemediation: "General fix",
    opensExternally: "(opens the official page in a new tab)",
  },
  standardsPanel: {
    note: 'The states say whether PGARD rules that map to an entry ran in this scan. "Rules ran" does not mean the project is safe or that the category is covered: see how many of its CWEs have rules (breadth). Only ids, titles and links are shown; see the linked pages for the standards themselves.',
    columns: {
      id: "ID",
      category: "Category",
      state: "State",
      breadth: "Breadth",
      rules: "Rules",
      reason: "Reason",
    },
    states: {
      rules_ran: "Rules ran",
      rules_partial: "Rules partial",
      not_run: "Not run",
      no_rules: "No rules",
    },
    breadth: (withRules: number, inCategory: number): string =>
      `${withRules} of ${inCategory} mapped CWEs have rules`,
    cweTop25Title: "CWE Top 25 2025",
    cweTop25Counts: (ran: number, partial: number, notRun: number, none: number): string =>
      `${ran} rules ran, ${partial} rules partial, ${notRun} not run, ${none} no rules`,
    cweColumns: { rank: "Rank", id: "CWE", name: "Weakness" },
    notRecorded:
      "Standards coverage and rule statistics were not recorded in this result (written by an older PGARD).",
    attributionTitle: "Standards data and attribution",
    attributionIntro:
      "Only identifiers, titles and links of these standards are shown here; none of their text is copied.",
    attributionOwasp:
      "OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc., licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/).",
    attributionCwe:
      "CWE and the CWE Top 25: Copyright (c) 2006-2026, The MITRE Corporation, used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). CWE is a trademark of The MITRE Corporation.",
    attributionCert:
      "SEI CERT Oracle Coding Standard for Java: (c) 2026 Carnegie Mellon University, licensed under CC BY 4.0. SEI CERT is a registered trademark of Carnegie Mellon University; this dashboard is not endorsed by Carnegie Mellon University or the SEI.",
  },
  ruleStats: {
    note: "What each rule examined in each area it ran in. A count of 0 findings means the rule found nothing in what it examined, not that the project is free of that weakness.",
    columns: {
      rule: "Rule",
      area: "Area",
      targets: "Targets examined",
      findings: "Findings",
      status: "Status",
    },
    targetCount: (examined: number, unit: string): string => `${examined} ${unit}`,
    targetUnknown: (reason: string): string => `unknown (${reason})`,
    summary: (count: number): string => `Rule statistics (${count})`,
  },
  nav: {
    label: "Dashboard sections",
    overview: "Overview",
    findings: "Findings",
    coverage: "Coverage",
    standards: "Standards",
    rules: "Rules",
    trend: "Trend",
    export: "Export",
  },
  strip: {
    label: "Scan controls",
    auth: {
      none: "Not verified",
      checking: "Checking authorization",
      signIn: "Waiting for GitHub sign-in",
      allowed: "Authorized",
      blocked: "Blocked",
      failed: "Check failed",
    },
    authDetails: "Details",
    target: (origin: string): string => `Web target ${origin}`,
    noTarget: "No web target",
    scanning: (time: string): string => `Scanning ${time}`,
  },
  overview: {
    noScan: "No scan yet. Verify the project, choose the scope and run a scan.",
    status: {
      completed: "Completed",
      partial: "Partial",
      blocked: "Blocked",
      failed: "Failed",
      unknown: "Unknown",
    },
    unfinished: (count: number): string => `${count} area${count === 1 ? "" : "s"} did not finish`,
    blockedDetail: "no analysis ran",
    failedDetail: "an internal error stopped the scan",
    stats: {
      findings: "Findings",
      confirmed: "Confirmed",
      suspected: "Suspected",
      informational: "Informational",
    },
    severityLabel: "Findings by severity",
    coverageTitle: "Coverage",
    coverageCounts: (completed: number, partial: number, notTested: number): string =>
      `${completed} completed · ${partial} partial · ${notTested} not tested`,
    coverageLink: "View coverage",
    topTitle: "Top findings",
    allFindings: (count: number): string => `View all ${count} findings`,
    summaryTitle: "Summary",
    statusMeaning: {
      confirmed: "Confirmed: the evidence shows the problem directly.",
      suspected: "Suspected: a risky pattern without enough evidence to confirm it; review it.",
      informational: "Informational: worth knowing, not proof of a vulnerability.",
    },
    severityBar: (summary: string): string => `Findings by severity: ${summary}`,
    severityFilterHint: "Select a severity to list only those findings.",
    partialMeaning:
      "Partial means only part of an area ran; the note says what is missing. Not tested means it could not run.",
    categoryTitle: "By category",
    categoryLink: (count: number, category: string): string =>
      `${count} ${category} findings, show them`,
    categoryEmpty: "No findings in any category.",
    scopeLine: "Scope",
    authAllowedWhy: "Every check passed, so scans of this repository may run.",
    authBlockedWhy:
      "A check failed, so no analysis runs. The failing check and how to fix it are below.",
    authNotChecked:
      "Verify the project before a scan: PGARD checks owner approval, your access and a merged contribution.",
  },
  categories: {
    injection: "Injection (SQL and others)",
    xss: "Cross-site scripting (XSS)",
    ssrf: "Server-side request forgery (SSRF)",
    access_control: "Access control",
    authentication: "Authentication",
    brute_force: "Brute force",
    cryptography: "Cryptography",
    misconfiguration: "Misconfiguration",
    csrf: "CSRF",
    file_handling: "File handling and paths",
    command_execution: "Command execution",
    secret_exposure: "Secrets",
  },
  help: {
    label: "About this section",
    authDetails: "Authorization details",
    signOut: "What the sign-out options do",
    session: "GitHub session",
  },
  linked: {
    barLabel: "Active filters",
    clearAll: "Clear all",
    clearAllLabel: "Clear all filters",
    remove: (filter: string): string => `Remove filter ${filter}`,
    fields: {
      severity: "Severity",
      status: "Status",
      source: "Source",
      category: "Category",
      rule: "Rule",
      area: "Area",
      path: "File",
      text: "Search",
    },
    chip: (field: string, value: string): string => `${field}: ${value}`,
    matching: (shown: number, total: number): string =>
      `${shown} of ${total} findings match the filters`,
    noMatch: "No findings match these filters. Remove a filter to see more.",
    filterCategory: (category: string, count: number): string =>
      `Filter by category ${category}, ${count} ${count === 1 ? "finding" : "findings"}`,
    filterArea: (area: string, count: number): string =>
      `Filter by area ${area}, ${count} ${count === 1 ? "finding" : "findings"}`,
    areaNone: (area: string): string => `${area}: no findings are linked to this area`,
    areaUndistinguishable: (area: string): string =>
      `${area}: findings cannot be reliably attributed to this area, so it cannot filter`,
    ofTotal: (total: number): string => `of ${total} (filtered)`,
    filterRule: (rule: string): string => `Filter by rule ${rule}`,
    filterFile: (file: string): string => `Filter by file ${file}`,
    hint: "Select a severity, category, area, rule or file to filter every panel and the table.",
  },
  table: {
    severity: "Severity",
    finding: "Finding",
    status: "Status",
    location: "Location",
    rule: "Rule",
    details: "Details",
    severityFilter: "Filter by severity",
    category: "Category",
  },
  trend: {
    title: "Trend",
    source:
      "Built from the scans you saved with the pgard command for this repository, matched by its GitHub repository id (the last 20 at most). Scans run in this dashboard are not stored, so they never appear here. A scan you just saved from a terminal can take a few seconds to appear.",
    loading: "Reading the saved scans...",
    loadFailed: "The saved scans could not be loaded.",
    reload: "Reload",
    disabled:
      "Saving scans is switched off, so there is no history to show. pgard dashboard honours only PGARD_NO_STORE=1; --no-store applies to pgard web. Allow storing and run pgard scan a few times to build a trend.",
    notVerified:
      "Verify the project first. Saved scans are matched to this repository only after the authorization check passes.",
    noStoreDir:
      "No folder for saved scans is available on this computer, so there is no history to show.",
    unreadable:
      "The saved scans could not be read, so no trend is shown. Nothing was changed; pgard history lists what is stored.",
    tooFew: (count: number): string =>
      count === 0
        ? "No saved scans for this repository yet. Run pgard scan (without --no-store) at least twice to see a trend."
        : "Only one saved scan for this repository. A trend needs at least two; run pgard scan again.",
    skipped: (count: number): string =>
      `${count} saved ${count === 1 ? "file" : "files"} could not be read and ${count === 1 ? "was" : "were"} left out.`,
    newerSkipped: (count: number): string =>
      `${count} saved ${count === 1 ? "scan was" : "scans were"} written by a newer PGARD and left out.`,
    futureSkipped: (count: number): string =>
      `${count} saved ${count === 1 ? "scan is" : "scans are"} dated in the future and left out, so the order stays correct.`,
    unread: (count: number): string =>
      `${count} older saved ${count === 1 ? "file was" : "files were"} not read (the view reads at most 20 usable scans).`,
    partialWarning: (count: number, total: number): string =>
      `${count} of ${total} scans did not cover everything (hatched). A lower count there can mean less was checked, not that findings were fixed.`,
    allComplete: "Every scan below completed all the areas it was asked to check.",
    severityTitle: "Findings by severity, scan by scan",
    chartLabel: (first: string, last: string, count: number): string =>
      `Stacked bars of active findings by severity for ${count} saved scans, from ${first} to ${last}. The table below lists every value.`,
    columnLabel: (date: string, total: number, breakdown: string, coverage: string): string =>
      `${date}: ${total} active findings (${breakdown}). Coverage: ${coverage}.`,
    activeLine: (total: number, breakdown: string): string =>
      `${total} active ${total === 1 ? "finding" : "findings"} (${breakdown})`,
    axisMax: (value: number): string => `${value}`,
    axisZero: "0",
    legendLabel: "Filter the trend by severity",
    legendHint:
      "Select a severity to highlight it here and to filter the Findings view. The trend counts by severity only; category and the other filters do not apply to it.",
    otherFilters:
      "Other active filters (category, area, rule, file, status, source, text) are kept but do not change the trend.",
    showFindings: "Show these findings in the current scan",
    noCurrentScan: "Run a scan in this dashboard to list the matching findings.",
    selectedTitle: "Selected scan",
    selectedHint: "Move between scans with the left and right arrow keys, or select a bar.",
    changeTitle: "Change between consecutive scans",
    changeChartLabel: (count: number): string =>
      `Bars of findings that are new and findings no longer reported, for ${count} scans compared with the scan before. The table below lists every value.`,
    legendNew: "New",
    legendGone: "No longer reported",
    legendUncertain: "Hatched: a scan involved did not cover everything",
    legendHatch: "Hatched bar: this scan did not cover everything",
    legendFlag: "Dash under a bar: this scan did not cover everything",
    changeNote:
      '"No longer reported" means the finding was in the earlier scan and its place was fully analyzed both times and it is gone. It is not proof that it was fixed.',
    changeCountsNote:
      "The new, no longer reported and unchanged counts compare every finding of the two scans, including ignored and baselined ones, so they can differ from the active counts in the bars.",
    ignoredBaselined:
      "Ignored findings are hidden by pgard.config.json; baselined findings are in the saved baseline. Neither is counted in the severity bars.",
    tableTitle: "Data table",
    tableCaption:
      "Saved scans of this repository, oldest first: active findings by severity, ignored and baselined findings, and the change since the scan before.",
    columns: {
      scan: "Saved",
      coverage: "Coverage",
      total: "Active",
      ignored: "Ignored",
      baselined: "Baselined",
      new: "New",
      gone: "No longer reported",
      unchanged: "Unchanged",
      notComparable: "Not comparable",
    },
    coverageValue: {
      completed: "Completed",
      partial: "Partial",
      not_tested: "Not tested",
    },
    coverageDetail: (status: string, areas: number): string =>
      areas === 0 ? status : `${status} (${areas} ${areas === 1 ? "area" : "areas"} incomplete)`,
    noChange: "First scan, or not comparable",
    changeSummary: (added: number, gone: number, same: number, unknown: number): string =>
      `${added} new, ${gone} no longer reported, ${same} unchanged, ${unknown} not comparable`,
    changeUncertainNote:
      "One of these two scans did not cover everything, so read these counts with care.",
  },
  report: {
    downloadHtml: "Download HTML",
    downloadPdf: "Download PDF",
    preparing: (format: string): string => `Preparing the ${format} report...`,
    downloaded: (filename: string): string =>
      `Downloaded ${filename}. Your browser saved it in its download folder.`,
    failed: "The report could not be downloaded. Run the scan again and retry.",
    sessionExpired:
      "The dashboard session is no longer valid. Open the private session URL printed by `pgard dashboard` again.",
    noResult: "There is no scan result to export yet. Run a scan first.",
    note: "Reports may describe sensitive weaknesses. Keep the downloaded file somewhere private.",
  },
} as const;
