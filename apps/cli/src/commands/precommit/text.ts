import type { RuleLocale } from "@pgard/findings";

/**
 * Fixed text of `pgard precommit` in both languages. Kept next to the command so a Korean entry
 * missing here fails the catalog test (`precommit.test.ts`). File names, option names, rule ids
 * and git commands stay as they are.
 */
export interface PrecommitText {
  notRepository: string;
  /** Printed first, to stderr. */
  checking: (budgetSeconds: number, timeoutSeconds: number) => string;
  repositoryUnsafe: (reason: string) => string;
  indexUnsafe: (reason: string) => string;
  /** The authorization gate blocked: nothing was scanned. */
  notAuthorized: string;
  authorizationHint: string;
  authorizationTimeout: (seconds: number) => string;
  scanFailed: string;
  /** Said when nothing (or not everything) was scanned. */
  notScannedHeading: string;
  incompleteHeading: string;
  skippedFile: (path: string, reason: string) => string;
  moreSkipped: (count: number) => string;
  configInvalid: (problems: string) => string;
  /** pgard.config.json exists in the working tree but is not staged or tracked. */
  configNotStaged: string;
  /** The working-tree pgard.config.json differs from the staged copy. */
  configDiffers: string;
  timeoutInvalid: (value: string, seconds: number) => string;
  /** The files skipped by design, named, so a skip is visible. */
  byDesign: (items: string) => string;
  byDesignKind: Record<
    "binary" | "symlink" | "submodule",
    (count: number, names: string) => string
  >;
  summary: (files: number, milliseconds: number) => string;
  findingsHeading: (count: number) => string;
  finding: (severity: string, ruleId: string, location: string, evidence: string) => string;
  moreFindings: (count: number) => string;
  hint: Record<"PG-SECRET-001" | "PG-SECRET-002", string>;
  preexisting: (count: number) => string;
  suppressedAndBaseline: (suppressed: number, inBaseline: number) => string;
  decisionClean: string;
  decisionBlockedFindings: string;
  decisionWarnFindings: string;
  decisionBlockedNotScanned: string;
  decisionWarnNotScanned: string;
  skipReason: Record<
    | "too_large"
    | "file_limit"
    | "byte_budget"
    | "time_budget"
    | "unmerged"
    | "unreadable"
    | "source_time",
    string
  >;
  /** Hook install. */
  install: {
    needsHooksDir: string;
    hooksPathInside: (hooksPath: string) => string;
    hooksPathOutside: (hooksPath: string) => string;
    unsafe: (reason: string) => string;
    existingNeedsTerminal: string;
    existingQuestion: (backup: string) => string;
    existingDeclined: string;
    installed: (file: string) => string;
    alreadyInstalled: (file: string) => string;
    backedUp: (backup: string) => string;
    globalHooksPathNote: string;
    failed: string;
    nextStep: string;
    mergeNote: string;
  };
  uninstall: {
    removed: (file: string) => string;
    notInstalled: string;
    notOurs: (file: string) => string;
    backupFound: (backup: string) => string;
    failed: string;
  };
  snippet: {
    heading: string;
    preCommitFramework: string;
    husky: string;
    plain: string;
    merge: string;
  };
}

const EN: PrecommitText = {
  notRepository:
    "The current directory is not inside a Git repository, so no staged changes could be scanned.",
  checking: (budgetSeconds, timeoutSeconds) =>
    `pgard precommit: checking authorization (up to ${timeoutSeconds} s), then the staged changes (up to ${budgetSeconds} s)...`,
  repositoryUnsafe: (reason) =>
    `The staged changes were NOT scanned: this repository layout cannot be read safely. ${reason}`,
  indexUnsafe: (reason) =>
    `The staged changes were NOT scanned: the index Git is committing could not be used safely. ${reason}`,
  notAuthorized:
    "The staged changes were NOT scanned: this repository is not authorized for PGARD (all five checks must pass, as for pgard scan).",
  authorizationHint:
    "Run `pgard project verify` to see what is missing. A commit hook never starts a sign-in; run `pgard login` once in a terminal.",
  authorizationTimeout: (seconds) =>
    `The staged changes were NOT scanned: the authorization check did not finish within ${seconds} s (GitHub unreachable or slow).`,
  scanFailed: "The staged changes were NOT scanned because of an internal error.",
  notScannedHeading: "Nothing was scanned.",
  incompleteHeading: "Not everything was scanned:",
  skippedFile: (path, reason) => `  - ${path}: ${reason}`,
  moreSkipped: (count) => `  ... and ${count} more`,
  configInvalid: (problems) =>
    `pgard.config.json is invalid and was ignored, so the strict default (block) applies: ${problems}`,
  configNotStaged:
    "pgard.config.json is not tracked in Git, so none of its settings are used here: the precommit settings (the strict default, block, applies), suppressions and exclude all come from the staged copy, and there is none. Only testDirectories is still read from the working-tree file. Run `git add pgard.config.json`.",
  configDiffers:
    "pgard.config.json in the working tree differs from the staged copy. The staged copy is used for the precommit settings, suppressions and exclude; only testDirectories is read from the working-tree file.",
  timeoutInvalid: (value, seconds) =>
    `PGARD_PRECOMMIT_TIMEOUT_MS=${value} is not a number from 1000 to 120000; using ${seconds} s.`,
  byDesign: (items) => `Not scanned by design: ${items}.`,
  byDesignKind: {
    binary: (count, names) => `${count} binary file(s) (${names})`,
    symlink: (count, names) => `${count} symbolic link(s) (${names})`,
    submodule: (count, names) => `${count} submodule(s) (${names})`,
  },
  summary: (files, milliseconds) =>
    `Scanned ${files} staged file(s) in ${milliseconds} ms (only lines this commit adds or changes are reported).`,
  findingsHeading: (count) => `${count} finding(s) in the staged changes:`,
  finding: (severity, ruleId, location, evidence) =>
    `  [${severity}] ${ruleId} ${location} - ${evidence}`,
  moreFindings: (count) => `  ... and ${count} more (run pgard scan for the full list)`,
  hint: {
    "PG-SECRET-001":
      "Do not commit .env files: `git restore --staged <file>`, add it to .gitignore, commit a .env.example without values.",
    "PG-SECRET-002":
      "Remove the value from the staged file and load it from the environment. If it was ever pushed, rotate it.",
  },
  preexisting: (count) =>
    `${count} finding(s) on lines this commit does not change were not reported (pgard scan lists them).`,
  suppressedAndBaseline: (suppressed, inBaseline) =>
    `Not counted: ${suppressed} suppressed by pgard.config.json, ${inBaseline} in the baseline.`,
  decisionClean: "Commit allowed: nothing found in the staged changes.",
  decisionBlockedFindings:
    "Commit BLOCKED (mode: block). Fix the findings, or use `git commit --no-verify` to skip this check once.",
  decisionWarnFindings: "Commit allowed (mode: warn): the findings above are warnings only.",
  decisionBlockedNotScanned:
    "Commit BLOCKED because the staged changes were not (fully) scanned (whenNotScanned: block). Use `git commit --no-verify` to skip this check once.",
  decisionWarnNotScanned:
    "WARNING: commit allowed, but the staged changes were not (fully) scanned (whenNotScanned: warn). Nothing was checked for the parts listed above.",
  skipReason: {
    too_large:
      "a text file over 1 MiB (binary files of any size are skipped by design); set whenNotScanned to warn to let such commits through",
    file_limit: "over the limit of 500 changed files",
    byte_budget: "over the total size limit (16 MiB)",
    time_budget: "the time cap was reached",
    unmerged: "unresolved merge conflict",
    unreadable: "could not be read",
    source_time: "source rules skipped, the time cap was reached",
  },
  install: {
    needsHooksDir: "The hooks directory could not be prepared.",
    hooksPathInside: (hooksPath) =>
      `This repository sets core.hooksPath=${hooksPath}, so Git ignores .git/hooks. PGARD does not write into it; add the snippet from \`pgard precommit snippet\` to the tool that manages those hooks.`,
    hooksPathOutside: (hooksPath) =>
      `This repository sets core.hooksPath=${hooksPath}, which points outside the repository. PGARD refuses to write a hook there.`,
    unsafe: (reason) => `Refused: ${reason}`,
    existingNeedsTerminal:
      "A pre-commit hook already exists and was not written by PGARD. Without a terminal PGARD will not replace it; run `pgard precommit install` in a terminal, or add `pgard precommit` to the hook yourself (see `pgard precommit snippet`).",
    existingQuestion: (backup) =>
      `A pre-commit hook that PGARD did not write already exists. Replace it? It is kept as ${backup}.`,
    existingDeclined: "Left the existing pre-commit hook unchanged.",
    installed: (file) => `Installed the pre-commit hook: ${file}`,
    alreadyInstalled: (file) => `The PGARD pre-commit hook is already installed: ${file}`,
    backedUp: (backup) => `The previous hook was kept as ${backup}.`,
    globalHooksPathNote:
      "Git ignores .git/hooks when core.hooksPath is set in your global or system Git config; PGARD only reads this repository's own config. Check with `git config --get core.hooksPath`.",
    failed: "The hook could not be written. Nothing was changed.",
    nextStep:
      'Set "precommit": { "mode": "warn" } in pgard.config.json (and commit it: the staged version counts) to print findings without blocking. Remove the hook with `pgard precommit uninstall`.',
    mergeNote:
      "Git runs pre-commit for ordinary commits and conflicted merges, but a clean merge commit runs pre-merge-commit instead. To check those too, see `pgard precommit snippet`.",
  },
  uninstall: {
    removed: (file) => `Removed the PGARD pre-commit hook: ${file}`,
    notInstalled: "No pre-commit hook is installed in this repository.",
    notOurs: (file) =>
      `${file} was not written by PGARD (or was changed afterwards); it was left unchanged.`,
    backupFound: (backup) => `An earlier hook is kept as ${backup}; move it back if you want it.`,
    failed: "The hook could not be removed. Nothing was changed.",
  },
  snippet: {
    heading: "Use `pgard precommit` from a hook manager instead of `pgard precommit install`:",
    preCommitFramework: "pre-commit framework (.pre-commit-config.yaml):",
    husky: "husky (.husky/pre-commit):",
    plain: "A plain hook (.git/hooks/pre-commit, executable):",
    merge:
      "A clean merge runs .git/hooks/pre-merge-commit, not pre-commit; put the same `pgard precommit` line there to check merge results. A merge is compared with HEAD (ours), so everything the other branch brings counts as added: it can pass the 500-file limit, which is reported as not scanned.",
  },
};

const KO: PrecommitText = {
  notRepository: "현재 디렉터리가 Git 저장소 안이 아니어서 스테이징된 변경을 검사하지 못했습니다.",
  checking: (budgetSeconds, timeoutSeconds) =>
    `pgard precommit: 권한을 확인한 뒤(최대 ${timeoutSeconds}초) 스테이징된 변경을 검사합니다(최대 ${budgetSeconds}초)...`,
  repositoryUnsafe: (reason) =>
    `스테이징된 변경을 검사하지 못했습니다: 이 저장소 구조는 안전하게 읽을 수 없습니다. ${reason}`,
  indexUnsafe: (reason) =>
    `스테이징된 변경을 검사하지 못했습니다: Git이 커밋하려는 인덱스를 안전하게 사용할 수 없습니다. ${reason}`,
  notAuthorized:
    "스테이징된 변경을 검사하지 못했습니다: 이 저장소는 PGARD 사용 권한이 확인되지 않았습니다(pgard scan과 같이 다섯 가지 확인이 모두 통과해야 합니다).",
  authorizationHint:
    "`pgard project verify`로 부족한 항목을 확인하세요. 커밋 훅은 로그인을 시작하지 않으니 터미널에서 `pgard login`을 한 번 실행하세요.",
  authorizationTimeout: (seconds) =>
    `스테이징된 변경을 검사하지 못했습니다: 권한 확인이 ${seconds}초 안에 끝나지 않았습니다(GitHub에 연결할 수 없거나 느립니다).`,
  scanFailed: "내부 오류로 스테이징된 변경을 검사하지 못했습니다.",
  notScannedHeading: "아무것도 검사하지 못했습니다.",
  incompleteHeading: "일부를 검사하지 못했습니다:",
  skippedFile: (path, reason) => `  - ${path}: ${reason}`,
  moreSkipped: (count) => `  ... 외 ${count}개`,
  configInvalid: (problems) =>
    `pgard.config.json이 올바르지 않아 무시했으므로 엄격한 기본값(block)을 적용합니다: ${problems}`,
  configNotStaged:
    "pgard.config.json이 Git에서 추적되지 않아 이 파일의 설정을 하나도 사용하지 않습니다. precommit 설정(엄격한 기본값 block 적용), 억제, exclude는 모두 스테이징된 사본에서 읽는데 사본이 없습니다. testDirectories만 작업 트리의 파일에서 읽습니다. `git add pgard.config.json`을 실행하세요.",
  configDiffers:
    "작업 트리의 pgard.config.json이 스테이징된 사본과 다릅니다. precommit 설정, 억제, exclude는 스테이징된 사본을 사용하고 testDirectories만 작업 트리의 파일에서 읽습니다.",
  timeoutInvalid: (value, seconds) =>
    `PGARD_PRECOMMIT_TIMEOUT_MS=${value}는 1000~120000 사이의 숫자가 아니어서 ${seconds}초를 사용합니다.`,
  byDesign: (items) => `설계상 검사하지 않음: ${items}.`,
  byDesignKind: {
    binary: (count, names) => `바이너리 파일 ${count}개(${names})`,
    symlink: (count, names) => `심볼릭 링크 ${count}개(${names})`,
    submodule: (count, names) => `서브모듈 ${count}개(${names})`,
  },
  summary: (files, milliseconds) =>
    `스테이징된 파일 ${files}개를 ${milliseconds}ms에 검사했습니다(이번 커밋이 추가하거나 바꾼 줄만 보고합니다).`,
  findingsHeading: (count) => `스테이징된 변경에서 발견 항목 ${count}개:`,
  finding: (severity, ruleId, location, evidence) =>
    `  [${severity}] ${ruleId} ${location} - ${evidence}`,
  moreFindings: (count) => `  ... 외 ${count}개(전체 목록은 pgard scan으로 확인하세요)`,
  hint: {
    "PG-SECRET-001":
      ".env 파일은 커밋하지 마세요. `git restore --staged <file>`로 스테이징을 취소하고 .gitignore에 추가한 뒤, 값 없는 .env.example을 커밋하세요.",
    "PG-SECRET-002":
      "스테이징된 파일에서 값을 지우고 환경 변수에서 불러오세요. 이미 푸시한 적이 있다면 값을 교체(rotate)하세요.",
  },
  preexisting: (count) =>
    `이번 커밋이 바꾸지 않은 줄의 발견 항목 ${count}개는 보고하지 않았습니다(pgard scan이 보여 줍니다).`,
  suppressedAndBaseline: (suppressed, inBaseline) =>
    `집계에서 제외: pgard.config.json 억제 ${suppressed}개, 기준선 ${inBaseline}개.`,
  decisionClean: "커밋 허용: 스테이징된 변경에서 발견된 항목이 없습니다.",
  decisionBlockedFindings:
    "커밋이 차단되었습니다(mode: block). 발견 항목을 고치거나, 이번 한 번만 `git commit --no-verify`로 이 검사를 건너뛰세요.",
  decisionWarnFindings: "커밋 허용(mode: warn): 위 발견 항목은 경고일 뿐입니다.",
  decisionBlockedNotScanned:
    "스테이징된 변경을 (모두) 검사하지 못해 커밋이 차단되었습니다(whenNotScanned: block). 이번 한 번만 `git commit --no-verify`로 건너뛸 수 있습니다.",
  decisionWarnNotScanned:
    "경고: 커밋은 허용되지만 스테이징된 변경을 (모두) 검사하지 못했습니다(whenNotScanned: warn). 위에 적은 부분은 전혀 확인되지 않았습니다.",
  skipReason: {
    too_large:
      "1 MiB를 넘는 텍스트 파일(바이너리 파일은 크기와 관계없이 설계상 건너뜁니다). 이런 커밋을 통과시키려면 whenNotScanned를 warn으로 설정하세요",
    file_limit: "변경 파일 500개 제한 초과",
    byte_budget: "전체 크기 제한(16 MiB) 초과",
    time_budget: "시간 제한에 도달함",
    unmerged: "해결되지 않은 병합 충돌",
    unreadable: "읽을 수 없음",
    source_time: "시간 제한에 도달해 소스 규칙을 건너뜀",
  },
  install: {
    needsHooksDir: "훅 디렉터리를 준비하지 못했습니다.",
    hooksPathInside: (hooksPath) =>
      `이 저장소는 core.hooksPath=${hooksPath}를 설정해 Git이 .git/hooks를 무시합니다. PGARD는 그 안에 쓰지 않습니다. 훅을 관리하는 도구에 \`pgard precommit snippet\`의 예시를 추가하세요.`,
    hooksPathOutside: (hooksPath) =>
      `이 저장소의 core.hooksPath=${hooksPath}는 저장소 밖을 가리킵니다. PGARD는 그곳에 훅을 쓰지 않습니다.`,
    unsafe: (reason) => `거부했습니다: ${reason}`,
    existingNeedsTerminal:
      "PGARD가 만들지 않은 pre-commit 훅이 이미 있습니다. 터미널이 없으면 PGARD는 덮어쓰지 않습니다. 터미널에서 `pgard precommit install`을 실행하거나, 훅에 `pgard precommit`을 직접 추가하세요(`pgard precommit snippet` 참고).",
    existingQuestion: (backup) =>
      `PGARD가 만들지 않은 pre-commit 훅이 이미 있습니다. 교체할까요? 기존 훅은 ${backup}로 보관합니다.`,
    existingDeclined: "기존 pre-commit 훅을 그대로 두었습니다.",
    installed: (file) => `pre-commit 훅을 설치했습니다: ${file}`,
    alreadyInstalled: (file) => `PGARD pre-commit 훅이 이미 설치되어 있습니다: ${file}`,
    backedUp: (backup) => `이전 훅은 ${backup}로 보관했습니다.`,
    globalHooksPathNote:
      "전역 또는 시스템 Git 설정에 core.hooksPath가 있으면 Git은 .git/hooks를 무시합니다. PGARD는 이 저장소의 설정만 읽습니다. `git config --get core.hooksPath`로 확인하세요.",
    failed: "훅을 쓰지 못했습니다. 아무것도 바꾸지 않았습니다.",
    nextStep:
      'pgard.config.json에 "precommit": { "mode": "warn" }을 넣고(스테이징된 버전이 적용되므로 커밋하세요) 차단하지 않고 발견 항목만 출력할 수 있습니다. 훅은 `pgard precommit uninstall`로 제거합니다.',
    mergeNote:
      "Git은 일반 커밋과 충돌이 있던 병합에는 pre-commit을 실행하지만, 충돌 없는 병합 커밋에는 pre-merge-commit을 실행합니다. 그것도 검사하려면 `pgard precommit snippet`을 참고하세요.",
  },
  uninstall: {
    removed: (file) => `PGARD pre-commit 훅을 제거했습니다: ${file}`,
    notInstalled: "이 저장소에는 설치된 pre-commit 훅이 없습니다.",
    notOurs: (file) => `${file}은(는) PGARD가 만들지 않았거나 이후에 수정되어 그대로 두었습니다.`,
    backupFound: (backup) => `이전 훅이 ${backup}로 보관되어 있습니다. 필요하면 되돌려 놓으세요.`,
    failed: "훅을 제거하지 못했습니다. 아무것도 바꾸지 않았습니다.",
  },
  snippet: {
    heading: "`pgard precommit install` 대신 훅 관리 도구에서 `pgard precommit`을 호출하려면:",
    preCommitFramework: "pre-commit 프레임워크(.pre-commit-config.yaml):",
    husky: "husky(.husky/pre-commit):",
    plain: "일반 훅(.git/hooks/pre-commit, 실행 권한 필요):",
    merge:
      "충돌 없는 병합은 pre-commit이 아니라 .git/hooks/pre-merge-commit을 실행합니다. 병합 결과도 검사하려면 같은 `pgard precommit` 줄을 거기에 넣으세요. 병합은 HEAD(ours)와 비교하므로 다른 브랜치가 가져오는 모든 내용이 추가된 것으로 취급되어 500개 파일 제한을 넘을 수 있고, 그 경우 검사하지 못한 것으로 보고합니다.",
  },
};

export function precommitText(locale: RuleLocale | undefined): PrecommitText {
  return locale === "ko" ? KO : EN;
}

export const PRECOMMIT_TEXT_CATALOG: Record<RuleLocale, PrecommitText> = { en: EN, ko: KO };
