import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { downloadToFile, osvArchiveUrl } from "./download.js";
import { NETWORK_CAUSE_CODES, networkCauseCode } from "./network-cause.js";

let dir: string | null = null;
afterEach(async () => {
  if (dir !== null) await rm(dir, { recursive: true, force: true });
  dir = null;
});

describe("the advisories download keeps the cause code", () => {
  it.each(NETWORK_CAUSE_CODES)("reports %s and never the raw error text", async (code) => {
    dir = await mkdtemp(path.join(os.tmpdir(), "pgard-net-"));
    const cause = Object.assign(new Error("connect to http://u:pw@proxy:3128"), { code });
    const failing = (async () => {
      throw new TypeError("fetch failed", { cause });
    }) as unknown as typeof fetch;
    const failure = await downloadToFile(osvArchiveUrl("npm"), path.join(dir, "a.zip"), {
      fetch: failing,
    }).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toMatchObject({
      code: "network",
      isUnreachable: true,
      causeCode: code,
      message: `The download failed (${code}).`,
    });
  });

  it("keeps the plain message when the reason is unknown or not whitelisted", async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "pgard-net-"));
    const failing = (async () => {
      throw new TypeError("fetch failed", { cause: { code: "EWEIRD" } });
    }) as unknown as typeof fetch;
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "a.zip"), { fetch: failing }),
    ).rejects.toMatchObject({ causeCode: null, message: "The download failed." });
    expect(networkCauseCode({ cause: { cause: { code: "ENOTFOUND" } } })).toBe("ENOTFOUND");
  });
});
