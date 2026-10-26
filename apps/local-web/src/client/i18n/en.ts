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
  common: {
    requestFailed: "Request failed.",
    none: "(none)",
    unknown: "unknown",
    all: "All",
  },
  app: {
    subtitle: (version: string | null): string =>
      `Local security dashboard${version === null ? "" : ` - v${version}`}`,
    footer:
      "Runs on 127.0.0.1 only. Dashboard scans are not stored: their results and the session are discarded when the dashboard stops.",
    errorNoToken:
      "This page needs the private session URL printed by `pgard dashboard`. Open that URL again.",
    errorSession: "The dashboard session is not available. Restart `pgard dashboard`.",
    errorRuleTexts:
      "Could not load the Korean rule texts. Rule titles and fix texts stay in English; reload the page to try again.",
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
      "The only external network traffic is to GitHub: the device-flow sign-in on github.com (and refreshing a saved sign-in there) and GitHub API calls that read what authorization needs (your identity, the app installation, your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub. The pgard doctor command also checks whether api.github.com is reachable.",
      "After authorization passes, PGARD sends one GET / to each discovered listening port on 127.0.0.1 to show its identity.",
      "PGARD does not ship or query a vulnerability database. Findings come from the code itself (query statements, server code, configuration), Git history and, if selected, local HTTP checks. Dependency versions are not checked against known vulnerabilities.",
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
    noDatabase:
      "PGARD does not ship or query a vulnerability database. Findings come from the code itself (query statements, server code, configuration), Git history and, if selected, local HTTP checks. Dependency versions are not checked against known vulnerabilities.",
    location: {
      unknownUrl: "(unknown URL)",
      unknownCommit: "unknown commit",
      commit: (sha: string): string => `commit ${sha}`,
      unknownLocation: "(unknown location)",
    },
  },
  details: {
    standards: "Standards",
    viaCwe: (cwe: string): string => `via ${cwe}`,
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
  charts: {
    barAria: (summary: string): string => `Findings by severity: ${summary}`,
    barTitle: (severity: string, count: number): string => `${severity}: ${count} finding(s)`,
    donutAria: (total: number): string => `${total} findings in total`,
    donutTitle: (severity: string, count: number, total: number): string =>
      `${severity}: ${count} of ${total}`,
    donutSingleTitle: (severity: string, total: number): string => `${severity}: ${total}`,
    findings: "findings",
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
