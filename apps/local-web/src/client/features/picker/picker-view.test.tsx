import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  PICKER_BLOCK_CODES,
  type PickerBlockCode,
  type PickerCandidate,
} from "../../../shared/picker-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { en } from "../../i18n/en";
import { ko } from "../../i18n/ko";
import { ProjectBar } from "./ProjectBar";
import { PickerView } from "./ProjectPicker";
import type { PickerControl } from "./use-picker";

afterEach(() => vi.unstubAllGlobals());

const noop = (): void => undefined;

function candidate(overrides: Partial<PickerCandidate> = {}): PickerCandidate {
  return {
    candidateId: "AAAAAAAAAAAAAAAAAAAAAA",
    name: "shop",
    displayPath: "~/code/shop",
    displayPathEscaped: null,
    collision: null,
    shown: "f".repeat(32),
    remote: { status: "github", repo: "acme/shop" },
    selectable: true,
    blocked: null,
    source: "scope",
    ...overrides,
  };
}

function control(overrides: Partial<PickerControl> = {}): PickerControl {
  return {
    scope: {
      roots: [
        { id: "RRRRRRRRRRRRRRRRRRRRRR", label: "~/code", enabled: true },
        { id: "SSSSSSSSSSSSSSSSSSSSSS", label: "~/Developer", enabled: false },
      ],
      limits: {
        minTypedNameLength: 2,
        maxNameLength: 255,
        maxDepth: 4,
        maxCandidates: 20,
        softBudgetSeconds: 5,
      },
      addCommand: "pgard web scope add <folder>",
    },
    recent: { entries: [], validating: false, ignored: false },
    phase: { kind: "idle" },
    nameProblem: null,
    droppedFile: false,
    error: null,
    candidate: null,
    isConfirming: false,
    submitTyped: noop,
    submitDrop: noop,
    cancelSearch: noop,
    choose: noop,
    back: noop,
    confirm: noop,
    removeRecent: noop,
    toggleRoot: noop,
    ...overrides,
  };
}

function render(language: "en" | "ko", node: React.ReactNode): string {
  vi.stubGlobal("navigator", { languages: [language] });
  return renderToStaticMarkup(<I18nProvider>{node}</I18nProvider>);
}

/** What `renderToStaticMarkup` does to text. */
const esc = (text: string): string =>
  text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");

const both = (node: () => React.ReactNode): { en: string; ko: string } => ({
  en: render("en", node()),
  ko: render("ko", node()),
});

describe("start screen", () => {
  it("shows the drop zone, a search box with the privacy attributes, recent list and search folders", () => {
    const html = both(() => <PickerView control={control()} />);
    expect(html.en).toContain("Drop a project folder here");
    expect(html.en).toContain("Only its name is used; nothing is uploaded.");
    expect(html.ko).toContain("프로젝트 폴더를 여기에 놓으세요");
    expect(html.ko).toContain("아무것도 업로드하지 않습니다");
    for (const text of Object.values(html)) {
      // The three attributes of T6: nothing about the name is kept by the browser.
      expect(text).toContain('autoComplete="off"');
      expect(text).toContain('autoCapitalize="off"');
      expect(text).toContain('spellCheck="false"');
      expect(text).toContain("pgard web scope add &lt;folder&gt;");
      expect(text).toContain("~/Developer");
    }
  });

  it("offers the add command as text to copy and never a path field", () => {
    const html = render("en", <PickerView control={control()} />);
    expect(html.match(/<input/g)?.filter(Boolean).length).toBe(3); // search + two root toggles
    expect(html).not.toMatch(/type="file"/);
    expect(html).not.toMatch(/webkitdirectory/);
    expect(html).toContain("Copy");
  });
});

describe("name rejected, dropped a file, searching", () => {
  it("names the actual problem and how to fix it", () => {
    const html = both(() => <PickerView control={control({ nameProblem: "slash" })} />);
    expect(html.en).toContain("That is not a folder name:");
    expect(html.en).toContain("it contains a `/` or `\\`.");
    expect(html.en).toContain(
      "Type only the folder&#x27;s own name, for example `shop`, not a path.",
    );
    expect(html.ko).toContain("폴더 이름이 아닙니다:");
    expect(html.ko).toContain("`shop`처럼");
  });

  it("says 'Drop a folder, not a file.' with the fix", () => {
    const html = both(() => <PickerView control={control({ droppedFile: true })} />);
    expect(html.en).toContain("Drop a folder, not a file.");
    expect(html.en).toContain("Drop the project&#x27;s folder.");
    expect(html.ko).toContain("파일이 아니라 폴더를 놓아 주세요.");
  });

  it("shows a spinner, the folders visited and a cancel button while searching", () => {
    const phase = {
      kind: "running",
      searchId: "x".repeat(22),
      name: "shop",
      visited: 321,
    } as const;
    const html = both(() => <PickerView control={control({ phase })} />);
    expect(html.en).toContain("Searching... 321 entries checked");
    expect(html.en).toContain("Cancel search");
    expect(html.ko).toContain("검색 중... 항목 321개 확인");
    expect(html.ko).toContain("검색 취소");
  });
});

describe("results", () => {
  const done = (candidates: PickerCandidate[], extra = {}) =>
    control({
      phase: {
        kind: "result",
        name: "shop",
        response: {
          status: "done",
          stoppedAfterSeconds: null,
          stoppedBy: null,
          uninspected: 0,
          visited: 9,
          candidates,
          skipped: [],
          ...extra,
        },
      },
    });

  it("no match: lists what to do and the command to copy, never a path field", () => {
    const html = both(() => <PickerView control={done([])} />);
    expect(html.en).toContain(
      "No Git repository named &quot;shop&quot; was found under the search folders.",
    );
    expect(html.en).toContain("add its parent folder in the terminal");
    expect(html.ko).toContain("라는 이름의 Git 저장소를 찾지 못했습니다");
  });

  it("partial: says when it stopped and what to do, and lists the not-checked folders", () => {
    const notChecked = candidate({
      name: "shop-two",
      selectable: false,
      remote: { status: "unreadable" },
      blocked: { code: "not_inspected", paths: [], reason: "x", fix: "y" },
    });
    const view = done([candidate(), notChecked], {
      status: "partial",
      stoppedAfterSeconds: 5.2,
      stoppedBy: "time",
      uninspected: 1,
    });
    const html = both(() => <PickerView control={view} />);
    expect(html.en).toContain("The search stopped after 5.2 s.");
    expect(html.en).toContain("Type more of the name");
    expect(html.en).toContain("1 folder was found but not checked in time");
    expect(html.en).toContain("The search ran out of time before this folder was checked.");
    expect(html.ko).toContain("5.2초 후 검색을 멈췄습니다.");
    expect(html.ko).toContain("제때 확인하지 못해");
    const limit = both(() => (
      <PickerView control={done([candidate()], { status: "partial", stoppedBy: "entries" })} />
    ));
    expect(limit.en).toContain("size limit");
    expect(limit.ko).toContain("크기 한도");
  });

  it("several matches: one card per candidate, choose by path and tag", () => {
    const twins = [
      candidate({ collision: { tag: "a1b2c3" } }),
      candidate({
        candidateId: "BBBBBBBBBBBBBBBBBBBBBB",
        displayPath: "~/work/shop",
        collision: { tag: "d4e5f6" },
        remote: { status: "github", repo: "acme/shop-2" },
      }),
    ];
    const html = both(() => <PickerView control={done(twins)} />);
    expect(html.en).toContain("Several folders match. Choose by path and tag, not by name.");
    expect(html.en).toContain("Tag a1b2c3");
    expect(html.en).toContain("Tag d4e5f6");
    expect(html.en).toContain("~/work/shop");
    expect(html.en).toContain("acme/shop-2");
    expect(html.ko).toContain("경로와 태그를 보고 고르세요");
    expect(html.ko).toContain("태그 a1b2c3");
  });

  it("renders hostile names as text, with the escaped form for an unsafe display path", () => {
    const hostile = candidate({
      name: "<img src=x onerror=alert(1)>",
      displayPath: "~/code/<script>alert(1)</script>",
      displayPathEscaped: "~/code/ev\\u{202e}il",
      selectable: false,
      blocked: { code: "unsafe_display", paths: [], reason: "x", fix: "y" },
    });
    const html = render("en", <PickerView control={done([hostile])} />);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("~/code/ev\\u{202e}il");
    expect(html).toContain("Path with non-printable characters escaped");
  });
});

describe("blocked states show what happened, why and what to do, in English and Korean (design test 17)", () => {
  const codes: PickerBlockCode[] = [...PICKER_BLOCK_CODES];

  it("has a text for every block code, in both languages, and nothing else", () => {
    expect(Object.keys(en.picker.blocked).sort()).toEqual([...codes].sort());
    expect(Object.keys(ko.picker.blocked).sort()).toEqual([...codes].sort());
  });

  for (const code of codes) {
    it(`renders ${code}`, () => {
      const blocked = candidate({
        selectable: false,
        remote: { status: "unreadable" },
        blocked: {
          code,
          paths: code === "group_or_world_writable" ? ["~/code", "~/code/shop/.git"] : [],
          reason: "server text",
          fix:
            code === "group_or_world_writable"
              ? "chmod go-w ~/code ~/code/shop/.git"
              : "server fix",
        },
        source: code === "outside_scope" ? "recent" : "scope",
      });
      const view = control({
        phase: {
          kind: "result",
          name: "shop",
          response: {
            status: "done",
            stoppedAfterSeconds: null,
            stoppedBy: null,
            uninspected: 0,
            visited: 1,
            candidates: [blocked],
            skipped: [],
          },
        },
      });
      const html = both(() => <PickerView control={view} />);
      expect(html.en).toContain(esc(en.picker.blocked[code].reason));
      expect(html.en).toContain(esc(en.picker.blocked[code].fix));
      expect(html.ko).toContain(esc(ko.picker.blocked[code].reason));
      expect(html.ko).toContain(esc(ko.picker.blocked[code].fix));
      // The server's own text is never shown: the page maps the code.
      expect(html.en).not.toContain("server text");
      expect(html.en).not.toContain("server fix");
      // A blocked candidate has no Choose button.
      expect(html.en).not.toContain(">Choose<");
      if (code === "group_or_world_writable") {
        expect(html.en).toContain("chmod go-w ~/code ~/code/shop/.git");
        expect(html.en).toContain("Folders and files to change");
      }
      if (code === "outside_scope") expect(html.en).toContain("pgard web scope add &lt;folder&gt;");
    });
  }
});

describe("candidate to confirm, recent list and errors", () => {
  it("shows the real path, owner/name, the remote rule and a Confirm button; it never says 'authorized'", () => {
    const view = control({ candidate: candidate({ collision: { tag: "a1b2c3" } }) });
    const html = both(() => <PickerView control={view} />);
    expect(html.en).toContain("This is the folder PGARD will read.");
    expect(html.en).toContain("~/code/shop");
    expect(html.en).toContain("The remote must be github.com/acme/shop.");
    expect(html.en).toContain("Next, PGARD checks that you are allowed to scan it.");
    expect(html.en).toContain("Confirm this project");
    expect(html.en).toContain("Tag a1b2c3");
    expect(html.en.toLowerCase()).not.toContain("authorized");
    expect(html.ko).toContain("PGARD가 읽을 폴더가 바로 이 폴더입니다.");
    expect(html.ko).toContain("원격 저장소는 github.com/acme/shop여야 합니다.");
    // The drop zone and search box are gone on the confirm screen.
    expect(html.en).not.toContain("Drop a project folder here");
  });

  it("shows recent entries with a remove button, a validating state and the ignored-file note", () => {
    const entry = {
      ...candidate({ source: "recent" }),
      entryId: "EEEEEEEEEEEEEEEEEEEEEE",
      lastUsedAt: "2026-10-28T09:00:00Z",
    };
    const html = both(() => (
      <PickerView
        control={control({ recent: { entries: [entry], validating: false, ignored: false } })}
      />
    ));
    expect(html.en).toContain("Recent projects");
    expect(html.en).toContain(">Recent<");
    expect(html.ko).toContain("최근 프로젝트");
    const validating = render(
      "en",
      <PickerView
        control={control({ recent: { entries: [], validating: true, ignored: false } })}
      />,
    );
    expect(validating).toContain("Checking recent projects...");
    const ignored = both(() => (
      <PickerView
        control={control({ recent: { entries: [], validating: false, ignored: true } })}
      />
    ));
    expect(ignored.en).toContain(
      "The recent list could not be read (damaged or from a newer PGARD). It is ignored.",
    );
    expect(ignored.ko).toContain("최근 목록을 읽을 수 없어");
    const blocked = {
      ...entry,
      selectable: false,
      blocked: { code: "outside_scope" as const, paths: [], reason: "x", fix: "y" },
    };
    const withRemove = render(
      "en",
      <PickerView
        control={control({ recent: { entries: [blocked], validating: false, ignored: false } })}
      />,
    );
    expect(withRemove).toContain("Remove from recent");
  });

  it("shows server errors as fixed text per code in both languages", () => {
    const html = both(() => (
      <PickerView control={control({ error: en.picker.errors.candidate_changed })} />
    ));
    expect(html.en).toContain(
      "The folder changed since you looked at it. Nothing was selected. Search again.",
    );
    expect(Object.keys(ko.picker.errors).sort()).toEqual(Object.keys(en.picker.errors).sort());
  });
});

describe("project bar and no leaks into the page", () => {
  const project = { name: "shop", repo: "acme/shop" };

  it("shows the project and owner/name, Change project, and Cancel check only while a check runs", () => {
    const idle = both(() => (
      <ProjectBar project={project} isScanRunning={false} isAuthRunning={false} onChanged={noop} />
    ));
    expect(idle.en).toContain("acme/shop");
    expect(idle.en).toContain("Change project");
    expect(idle.en).not.toContain("Cancel check");
    expect(idle.ko).toContain("프로젝트 변경");
    const checking = both(() => (
      <ProjectBar project={project} isScanRunning={false} isAuthRunning onChanged={noop} />
    ));
    expect(checking.en).toContain("Cancel check");
    expect(checking.en).toContain("A check is running. Cancel the check first.");
    expect(checking.en).toMatch(/<button[^>]*disabled[^>]*>Change project/);
    expect(checking.ko).toContain("확인 취소");
    const scanning = render(
      "en",
      <ProjectBar project={project} isScanRunning isAuthRunning={false} onChanged={noop} />,
    );
    expect(scanning).toContain("A scan is running. Cancel it first.");
    expect(scanning).toMatch(/<button[^>]*disabled[^>]*>Change project/);
  });

  it("never puts a name or path into document.title, the location, history or localStorage", () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const sources = readdirSync(here)
      .filter((file) => /\.(ts|tsx)$/.test(file) && !/\.test\./.test(file))
      .map((file) => readFileSync(path.join(here, file), "utf8"))
      .join("\n");
    for (const forbidden of [
      /document\.title/,
      /location\.(href|hash|search|assign|replace)/,
      /history\.(pushState|replaceState)/,
      /localStorage/,
      /sessionStorage/,
      /dangerouslySetInnerHTML/,
      /console\./,
    ]) {
      expect(sources, String(forbidden)).not.toMatch(forbidden);
    }
    expect(sources).not.toMatch(
      /\.getAsFile\(|new FileReader|\.createReader\(|webkitdirectory|showDirectoryPicker/,
    );
  });
});
