import type { WebStorage } from "@pgard/result-store";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PickerBrowseResponse, PickerPathResponse } from "../shared/picker-types.js";
import { createFolderDialog, dialogCommandFor, type FolderDialog } from "./picker/folder-dialog.js";
import { expandPastedPath } from "./picker/choose-folder.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  json,
  result,
  send,
  startHarness,
  TOKEN,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

/** The OS folder dialog and the pasted path of the simple screen (#414). */

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

const SHOP = "/home/u/code/shop";
const NOTES = "/home/u/code/notes";

function notGit(name: string) {
  return repoCandidate(name, {
    block: { code: "not_a_git_root", paths: [] },
    remote: { status: "unreadable" },
  });
}

/** A dialog the test closes by hand. */
function manualDialog(): {
  dialog: FolderDialog;
  calls: Array<{ prompt: string; signal: AbortSignal }>;
  answer: (value: Awaited<ReturnType<FolderDialog>>) => void;
} {
  const calls: Array<{ prompt: string; signal: AbortSignal }> = [];
  let settle: (value: Awaited<ReturnType<FolderDialog>>) => void = () => undefined;
  const dialog: FolderDialog = (options) => {
    calls.push(options);
    return new Promise((resolve) => {
      settle = resolve;
      options.signal.addEventListener("abort", () => resolve({ status: "cancelled" }));
    });
  };
  return { dialog, calls, answer: (value) => settle(value) };
}

async function pathCandidate(h: Harness, pasted: string): Promise<PickerPathResponse> {
  const response = await apiPost(h.server, "/api/picker/path", { path: pasted });
  expect(response.status).toBe(200);
  return json(response) as unknown as PickerPathResponse;
}

describe("pasted path", () => {
  it("is on in picker mode without any flag, and refused in fixed mode", async () => {
    harness = await startHarness();
    expect(json(await apiGet(harness.server, "/api/session")).ui).toBe("simple");
    expect((await apiGet(harness.server, "/api/picker/browse")).status).toBe(200);
    await harness.close();
    harness = await startHarness({ fixedRoot: "/home/u/code/shop" });
    expect((await apiPost(harness.server, "/api/picker/path", { path: SHOP })).status).toBe(409);
    expect((await apiPost(harness.server, "/api/picker/browse", {})).status).toBe(409);
  });

  it("keeps the token and Origin checks", async () => {
    harness = await startHarness();
    const port = harness.server.port;
    const noToken = await send(harness.server, "POST", "/api/picker/path", {
      headers: { origin: `http://127.0.0.1:${port}`, "content-type": "application/json" },
      body: JSON.stringify({ path: SHOP }),
    });
    expect(noToken.status).toBe(401);
    const foreign = await send(harness.server, "POST", "/api/picker/browse", {
      headers: {
        origin: "http://evil.example",
        "content-type": "application/json",
        "x-pgard-token": TOKEN,
      },
      body: "{}",
    });
    expect(foreign.status).toBe(403);
  });

  it("expands ~, resolves in the inspector and confirms a GitHub repository normally", async () => {
    // A folder chosen in the dialog or pasted is never written to the recent list.
    const writeRecent = vi.fn(async () => ({ status: "ok" }) as const);
    const readRecent = vi.fn(async () => ({ status: "ok", value: [] }) as const);
    const storage = { readRecent, writeRecent } as unknown as WebStorage;
    harness = await startHarness({ picker: { storage } });
    harness.inspector.resolved.set(SHOP, { candidate: repoCandidate("shop"), folderBlock: null });
    const { candidate, refusal } = await pathCandidate(harness, "  ~/code/shop  ");
    expect(refusal).toBeNull();
    expect(candidate?.selectable).toBe(true);
    expect(candidate?.codeOnly).toBeUndefined();
    expect(candidate?.displayPath).toBe("~/code/shop");
    const job = harness.inspector.runs.find((run) => run.job.kind === "resolve")?.job;
    expect(job).toEqual({ kind: "resolve", path: SHOP, homeDir: "/home/u" });
    const confirmed = await apiPost(harness.server, "/api/picker/confirm", {
      candidateId: candidate!.candidateId,
      shown: candidate!.shown,
      epoch: harness.server.state.projectEpoch,
    });
    expect(confirmed.status).toBe(200);
    expect(harness.server.state.project?.identity?.kind).not.toBe("folder");
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(writeRecent).not.toHaveBeenCalled();
  });

  it("makes a folder without Git selectable for a code-only scan only", async () => {
    const runCodeOnlyScan = vi.fn(async () =>
      result({ target: { repo: null, revision: null, webOrigin: null } }),
    );
    const verifyProject = vi.fn();
    harness = await startHarness({ deps: { runCodeOnlyScan, verifyProject } });
    harness.inspector.resolved.set(NOTES, { candidate: notGit("notes"), folderBlock: null });
    const { candidate } = await pathCandidate(harness, NOTES);
    expect(candidate?.selectable).toBe(true);
    expect(candidate?.codeOnly).toBe("not_git");
    expect(candidate?.blocked).toBeNull();
    const confirmed = await apiPost(harness.server, "/api/picker/confirm", {
      candidateId: candidate!.candidateId,
      shown: candidate!.shown,
      epoch: harness.server.state.projectEpoch,
    });
    expect(confirmed.status).toBe(200);
    expect(json(confirmed).project).toEqual({ name: "notes", repo: null });
    const epoch = harness.server.state.projectEpoch;
    // Every route that runs the authorization gate refuses a code-only folder.
    const verify = await apiPost(harness.server, "/api/auth/verify", { epoch });
    expect(verify.status).toBe(409);
    expect((json(verify).error as { code: string }).code).toBe("code_only_project");
    expect(verifyProject).not.toHaveBeenCalled();
    const authorized = await apiPost(harness.server, "/api/scan", { epoch, scopes: ["code"] });
    expect(authorized.status).toBe(409);
    // The code-only scan runs, after the folder chain is checked again.
    const started = await apiPost(harness.server, "/api/code-scan", { epoch });
    expect(started.status).toBe(200);
    await waitFor(
      async () => json(await apiGet(harness!.server, "/api/scan")),
      (value) => value.status === "done",
    );
    expect(runCodeOnlyScan).toHaveBeenCalledOnce();
    const folderChecks = harness.inspector.runs.filter(
      (run) => run.job.kind === "inspect" && run.job.mode === "folder",
    );
    expect(folderChecks.length).toBeGreaterThanOrEqual(2);
  });

  it("refuses a code-only scan when the folder became writable by others", async () => {
    harness = await startHarness();
    harness.inspector.resolved.set(NOTES, { candidate: notGit("notes"), folderBlock: null });
    const { candidate } = await pathCandidate(harness, NOTES);
    await apiPost(harness.server, "/api/picker/confirm", {
      candidateId: candidate!.candidateId,
      shown: candidate!.shown,
      epoch: harness.server.state.projectEpoch,
    });
    harness.inspector.folderBlock = { code: "group_or_world_writable", paths: [NOTES] };
    const started = await apiPost(harness.server, "/api/code-scan", {
      epoch: harness.server.state.projectEpoch,
    });
    expect(started.status).toBe(409);
    expect((json(started).error as { code: string }).code).toBe("candidate_changed");
  });

  it("refuses a folder whose chain another user could change, without .git wording", async () => {
    harness = await startHarness();
    harness.inspector.resolved.set(NOTES, {
      candidate: notGit("notes"),
      folderBlock: { code: "group_or_world_writable", paths: [NOTES] },
    });
    const { candidate, refusal } = await pathCandidate(harness, NOTES);
    expect(candidate).toBeNull();
    expect(refusal?.code).toBe("group_or_world_writable");
    expect(refusal?.paths).toEqual(["~/code/notes"]);
    expect(JSON.stringify(refusal)).not.toContain(".git");
  });

  it("shows refused paths through the display-safety check", async () => {
    harness = await startHarness();
    const spoofed = "/home/u/evil\u202ecod.js";
    harness.inspector.resolved.set(NOTES, {
      candidate: notGit("notes"),
      folderBlock: { code: "not_owned_by_you", paths: [spoofed] },
    });
    const chain = await pathCandidate(harness, NOTES);
    expect(chain.refusal?.paths).toEqual(["~/evil\\u{202e}cod.js"]);
    harness.inspector.resolved.set("/home/u/deep", { refused: "too_deep", paths: [spoofed] });
    const deep = await pathCandidate(harness, "/home/u/deep");
    expect(deep.refusal?.paths).toEqual(["~/evil\\u{202e}cod.js"]);
  });

  it("returns refusals with a reason and a fix", async () => {
    harness = await startHarness();
    harness.inspector.resolved.set("/home/u", { refused: "too_broad" });
    const home = await pathCandidate(harness, "~");
    expect(home.refusal?.code).toBe("too_broad");
    expect(home.refusal?.fix).toContain("~/code/my-app");
    expect((await pathCandidate(harness, "code/shop")).refusal?.code).toBe("bad_path");
    expect((await pathCandidate(harness, "~other/x")).refusal?.code).toBe("bad_path");
    expect((await pathCandidate(harness, "/home/u/gone")).refusal?.code).toBe("missing");
    const runsBefore = harness.inspector.runs.length;
    expect((await pathCandidate(harness, "/a\0b")).refusal?.code).toBe("bad_path");
    expect((await pathCandidate(harness, `/${"a".repeat(5000)}`)).refusal?.code).toBe("bad_path");
    expect(harness.inspector.runs.length).toBe(runsBefore);
  });
});

describe("OS folder dialog (prototype)", () => {
  it("opens one dialog at a time, polls, and returns the chosen folder", async () => {
    const manual = manualDialog();
    harness = await startHarness({ picker: { folderDialog: manual.dialog } });
    harness.inspector.resolved.set(SHOP, { candidate: repoCandidate("shop"), folderBlock: null });
    const opened = await apiPost(harness.server, "/api/picker/browse", { lang: "ko" });
    expect((json(opened) as unknown as PickerBrowseResponse).status).toBe("open");
    expect(manual.calls[0]?.prompt).toBe("검사할 프로젝트 폴더를 선택하세요");
    const second = await apiPost(harness.server, "/api/picker/browse", {});
    expect(second.status).toBe(409);
    expect((json(second).error as { code: string }).code).toBe("dialog_open");
    manual.answer({ status: "chosen", path: `${SHOP}/` });
    const done = (await waitFor(
      async () => json(await apiGet(harness!.server, "/api/picker/browse")),
      (value) => value.status !== "open",
    )) as unknown as PickerBrowseResponse;
    expect(done.status).toBe("chosen");
    expect(done.candidate?.displayPath).toBe("~/code/shop");
    expect(JSON.stringify(done)).not.toContain(SHOP);
  });

  it("treats cancel as a normal state and kills the dialog on cancel", async () => {
    const manual = manualDialog();
    harness = await startHarness({ picker: { folderDialog: manual.dialog } });
    await apiPost(harness.server, "/api/picker/browse", {});
    const cancelled = await apiPost(harness.server, "/api/picker/browse/cancel", {});
    expect(cancelled.status).toBe(200);
    expect((json(cancelled) as unknown as PickerBrowseResponse).status).toBe("cancelled");
    expect(manual.calls[0]?.signal.aborted).toBe(true);
    // A new one can be opened afterwards; the user closing it is "cancelled", not an error.
    await apiPost(harness.server, "/api/picker/browse", {});
    manual.answer({ status: "cancelled" });
    const status = await waitFor(
      async () => json(await apiGet(harness!.server, "/api/picker/browse")),
      (value) => value.status !== "open",
    );
    expect(status.status).toBe("cancelled");
  });

  it("closes the dialog when the server stops", async () => {
    const manual = manualDialog();
    harness = await startHarness({ picker: { folderDialog: manual.dialog } });
    await apiPost(harness.server, "/api/picker/browse", {});
    await harness.close();
    harness = null;
    expect(manual.calls[0]?.signal.aborted).toBe(true);
  });

  it("says when no dialog is available", async () => {
    harness = await startHarness({ picker: { folderDialog: undefined } });
    const opened = await apiPost(harness.server, "/api/picker/browse", {});
    expect((json(opened) as unknown as PickerBrowseResponse).status).toBe("unavailable");
  });
});

describe("folder dialog commands", () => {
  it("uses fixed argv per platform with only our prompt in it", async () => {
    const mac = await dialogCommandFor("darwin", 'Pick "x"');
    expect(mac?.file).toBe("/usr/bin/osascript");
    expect(mac?.args.at(-1)).toBe('POSIX path of (choose folder with prompt "Pick \\"x\\"")');
    // Windows is not supported by the picker (POSIX-only folder checks): no dialog.
    expect(await dialogCommandFor("win32", "Pick", async () => true)).toBeNull();
    const linux = await dialogCommandFor("linux", "Pick", async (file) => file.endsWith("kdialog"));
    expect(linux).toEqual({
      file: "/usr/bin/kdialog",
      args: ["--getexistingdirectory", "--title", "Pick"],
      cancelCodes: [1],
    });
    expect(await dialogCommandFor("linux", "Pick", async () => false)).toBeNull();
  });

  it("maps exit codes and output to the dialog states", async () => {
    const signal = new AbortController().signal;
    const run = (code: number | null, stdout = "", timedOut = false) =>
      createFolderDialog({ platform: "darwin", run: async () => ({ code, stdout, timedOut }) })({
        prompt: "p",
        signal,
      });
    expect(await run(0, "/Users/u/code/shop/\n")).toEqual({
      status: "chosen",
      path: "/Users/u/code/shop/",
    });
    expect(await run(1)).toEqual({ status: "cancelled" });
    expect(await run(null)).toEqual({ status: "unavailable" });
    expect(await run(null, "", true)).toEqual({ status: "timeout" });
    expect(
      await createFolderDialog({ platform: "linux", isExecutable: async () => false })({
        prompt: "p",
        signal,
      }),
    ).toEqual({ status: "unavailable" });
  });

  it("expands only ~ and ~/ and refuses everything that is not an absolute path", () => {
    expect(expandPastedPath("~", "/home/u")).toBe("/home/u");
    expect(expandPastedPath("~/code/../code/shop/", "/home/u")).toBe("/home/u/code/shop");
    expect(expandPastedPath("~bob/x", "/home/u")).toBeNull();
    expect(expandPastedPath("./x", "/home/u")).toBeNull();
    expect(expandPastedPath(42, "/home/u")).toBeNull();
    expect(expandPastedPath("/", "/home/u")).toBe("/");
  });
});
