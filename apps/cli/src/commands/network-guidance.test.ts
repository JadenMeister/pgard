import {
  createUnavailableCredentialStore,
  GitHubAuthError,
  type NetworkCauseCode,
} from "@pgard/scan-core";
import type { UpdateOutcome } from "@pgard/dependencies";
import { describe, expect, it } from "vitest";
import { main } from "../app.js";
import type { HostProbe } from "../deps.js";
import { createTestContext, createTestDeps, createTestIo, noInterrupts } from "../test-support.js";
import { COMMAND_TEXT_EN, COMMAND_TEXT_KO } from "../ui/i18n/command-text.js";
import { runDoctor } from "./doctor.js";
import { runLogin } from "./login.js";

const OSV = "osv-vulnerabilities.storage.googleapis.com";
const ENV = { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liTestClient" };

function terminalIo(locale?: "ko") {
  const captured = createTestIo({ env: ENV });
  captured.stdin.isTTY = true;
  (captured.io.stderr as { isTTY?: boolean }).isTTY = true;
  return { captured, context: (deps = createTestDeps()) => ctx(captured, deps, locale) };
}

function ctx(
  captured: ReturnType<typeof createTestIo>,
  deps: ReturnType<typeof createTestDeps>,
  locale?: "ko",
) {
  const base = createTestContext(captured, deps);
  return locale === undefined ? base : { ...base, ruleLocale: locale };
}

const probes = (down: Record<string, string | null>): (() => Promise<HostProbe[]>) => {
  return async () =>
    ["github.com", "api.github.com", OSV].map((host) => ({
      host,
      isReachable: !(host in down),
      causeCode: down[host] ?? null,
    }));
};

describe("pgard doctor network rows", () => {
  it("probes the three hosts and shows each as reachable", async () => {
    const captured = createTestIo();
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    const out = captured.stdout();
    expect(out).toContain("GitHub sign-in reachability: github.com reachable");
    expect(out).toContain("GitHub API reachability: api.github.com reachable");
    expect(out).toContain(`Advisory host reachability: ${OSV} reachable`);
  });

  it.each([
    ["ENOTFOUND", "HTTPS_PROXY"],
    ["ECONNREFUSED", "NODE_USE_ENV_PROXY=1"],
    ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "NODE_EXTRA_CA_CERTS"],
    ["SELF_SIGNED_CERT_IN_CHAIN", "NODE_EXTRA_CA_CERTS"],
  ])("shows %s with the matching hint", async (cause, hint) => {
    const captured = createTestIo();
    const deps = createTestDeps({ probeHosts: probes({ "api.github.com": cause }) });
    expect(await runDoctor(createTestContext(captured, deps))).toBe(0);
    const line = captured
      .stdout()
      .split("\n")
      .find((row) => row.includes("api.github.com not reachable"));
    expect(line).toContain("[fail]");
    expect(line).toContain(`(${cause})`);
    expect(line).toContain(hint);
    expect(captured.stdout()).toContain("1 required check(s) need attention");
  });

  it("marks an unreachable advisory host as a warning, with an unknown cause left out", async () => {
    const captured = createTestIo();
    const deps = createTestDeps({ probeHosts: probes({ [OSV]: null }) });
    await runDoctor(createTestContext(captured, deps));
    const line = captured
      .stdout()
      .split("\n")
      .find((row) => row.includes(`${OSV} not reachable`));
    expect(line).toContain("[warn]");
    expect(line).not.toContain("()");
    expect(line).toContain("HTTPS_PROXY");
  });

  it("says it in Korean", async () => {
    const captured = createTestIo();
    const deps = createTestDeps({
      probeHosts: probes({ "github.com": "SELF_SIGNED_CERT_IN_CHAIN" }),
    });
    await runDoctor(ctx(captured, deps, "ko"));
    expect(captured.stdout()).toContain(
      "github.com에 연결할 수 없음 (SELF_SIGNED_CERT_IN_CHAIN). TLS를 검사하는 프록시가 끼어 있을 수 있습니다.",
    );
  });
});

describe("pgard login network failure", () => {
  const failing = (code: NetworkCauseCode | null) =>
    createTestDeps({
      signInAndStore: async () => {
        throw new GitHubAuthError(
          "network_error",
          code === null
            ? "Could not reach GitHub for sign-in."
            : `Could not reach GitHub for sign-in (${code}).`,
          null,
          code,
        );
      },
    });

  it("keeps the cause code and points to the proxy variables and --code-only", async () => {
    const { captured, context } = terminalIo();
    expect(await runLogin(context(failing("ENOTFOUND")))).toBe(3);
    const err = captured.stderr();
    expect(err).toContain("Could not reach GitHub for sign-in (ENOTFOUND).");
    expect(err).toContain("HTTPS_PROXY and NODE_USE_ENV_PROXY=1 (Node 24 and newer)");
    expect(err).toContain("`pgard scan code --code-only`");
  });

  it("points a certificate failure to NODE_EXTRA_CA_CERTS, in Korean too", async () => {
    const en = terminalIo();
    await runLogin(en.context(failing("UNABLE_TO_VERIFY_LEAF_SIGNATURE")));
    expect(en.captured.stderr()).toContain("NODE_EXTRA_CA_CERTS=<path to your company CA file>");
    const ko = terminalIo("ko");
    await runLogin(ko.context(failing("UNABLE_TO_VERIFY_LEAF_SIGNATURE")));
    expect(ko.captured.stderr()).toContain("NODE_EXTRA_CA_CERTS=<회사 CA 파일 경로>");
    expect(ko.captured.stderr()).toContain("`pgard scan code --code-only`");
  });

  it("adds no hint to other sign-in failures", async () => {
    const { captured, context } = terminalIo();
    const deps = createTestDeps({
      signInAndStore: async () => {
        throw new GitHubAuthError("access_denied", "GitHub sign-in was denied by the user.");
      },
    });
    await runLogin(context(deps));
    expect(captured.stderr()).not.toContain("HTTPS_PROXY");
  });
});

describe("keychain unavailable remedies", () => {
  it("login names the Secret Service, a D-Bus session and --code-only", async () => {
    const { captured, context } = terminalIo();
    const deps = createTestDeps({
      credentialStore: createUnavailableCredentialStore("no keychain service is running"),
    });
    expect(await runLogin(context(deps))).toBe(4);
    const err = captured.stderr();
    expect(err).toContain("Secret Service (gnome-keyring, or KeePassXC with libsecret)");
    expect(err).toContain("D-Bus session");
    expect(err).toContain("`pgard scan code --code-only`");
    expect(err).toContain("ask for a device code on each run");
  });

  it("has the same remedies in the memory-only notice and in Korean", () => {
    for (const text of [COMMAND_TEXT_EN, COMMAND_TEXT_KO]) {
      expect(text.signIn.memoryOnly("x")).toContain("gnome-keyring");
      expect(text.signIn.memoryOnly("x")).toContain("--code-only");
      expect(text.signIn.keychainUnavailableOnLogin("x")).toContain("D-Bus");
      expect(text.signIn.keychainUnavailableOnLogin("x")).toContain("--code-only");
    }
    expect(COMMAND_TEXT_KO.signIn.memoryOnly("x")).toContain(
      "다음 실행에서는 기기 코드를 다시 요청합니다",
    );
  });
});

describe("pgard advisories update network failure", () => {
  const outcome = (causeCode: string | null): UpdateOutcome => ({
    ecosystem: "npm",
    ok: false,
    error: causeCode === null ? "The download failed." : `The download failed (${causeCode}).`,
    unreachable: { causeCode },
  });

  it.each([
    ["ENOTFOUND", "HTTPS_PROXY"],
    ["SELF_SIGNED_CERT_IN_CHAIN", "NODE_EXTRA_CA_CERTS"],
    [null, "HTTPS_PROXY"],
  ])("with cause %s prints the hint and the host to allow", async (cause, hint) => {
    const captured = createTestIo();
    const code = await main(["advisories", "update"], captured.io, {
      deps: createTestDeps({ updateAdvisories: (async () => [outcome(cause)]) as never }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(4);
    const out = captured.stdout();
    if (cause !== null) expect(out).toContain(`(${cause})`);
    expect(out).toContain(hint);
    expect(out).toContain(`Allow ${OSV} on https`);
    expect(out).not.toContain("--code-only");
  });
});
