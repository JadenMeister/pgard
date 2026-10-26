/**
 * JSON shapes exchanged between the local server and the browser. Browser-safe: types only.
 * Results are the redacted v1 ScanResult; no source code, tokens or absolute project paths.
 */
import type { AuthorizationSummary, ScanResult, ScanScope } from "@pgard/findings";

export const SESSION_TOKEN_HEADER = "x-pgard-token";

export interface ApiError {
  error: { code: string; message: string };
}

export interface SessionInfo {
  version: string;
  /** Last path segment of the project root only; the full path stays in the terminal. */
  projectName: string;
  /** Port pre-selected with `pgard dashboard --target-port`; still needs confirmation. */
  presetTargetPort: number | null;
  /**
   * The GitHub App the server signs in with: the built-in PGARD App, or the
   * `PGARD_GITHUB_APP_CLIENT_ID` override. The client id is public (device flow, no secret).
   */
  githubApp:
    | {
        clientId: string;
        /** Install-page slug; `null` when the client id is overridden without a slug. */
        slug: string | null;
        source: "default" | "env";
      }
    /**
     * An override (client id or slug) is set but malformed: identity is unverifiable and every
     * scan is blocked. `message` is fixed text naming the override, never its value.
     */
    | { clientId: null; slug: null; source: "invalid"; message: string };
  /**
   * Fixed warning when `PGARD_GITHUB_APP_SLUG` is overridden but the built-in client id is used
   * (the install link would point to another App); otherwise `null`.
   */
  githubAppWarning: string | null;
}

export interface DeviceCodeInfo {
  userCode: string;
  verificationUri: string;
  expiresIn: number;
}

export type JobStatus = "idle" | "running" | "done" | "failed";

/**
 * Same shape as `OwnerApprovalRemedy` from `@pgard/policy` (the CLI shows the same data): owner
 * approval failed only because the PGARD GitHub App is not installed for this repository.
 * Guidance only; installing the App is the owner's approval and the full check runs again.
 */
export interface InstallRemedyDto {
  kind: "install_app";
  missing: "installation" | "repository" | "access" | "repository_access";
  account: { login: string; type: "User" | "Organization" };
  /**
   * Always an `https://github.com/...` URL, or `null` (see `unavailableReason`): the App's
   * install page (`/apps/...`), or for `repository_access` the existing installation's settings
   * page (`/settings/installations/<id>` or `/organizations/<org>/settings/installations/<id>`).
   */
  url: string | null;
  /**
   * `yes`: personal owner or active organization owner; `no`: GitHub shows they are not;
   * `unknown`: the organization membership could not be read yet (guided like `yes`).
   */
  canApprove: "yes" | "no" | "unknown";
  unavailableReason: string | null;
}

/** `POST /api/auth/owner-approval`: owner approval alone, checked again. Never an authorization. */
export interface OwnerApprovalRecheckDto {
  status: "passed" | "failed" | "unverifiable";
  reason: string;
  /** Still the install remedy while the App is missing; `null` once something changed. */
  remedy: InstallRemedyDto | null;
}

/**
 * The GitHub sign-in saved in the OS keychain, as the browser may see it: the account login at
 * most. The token itself stays in the local server process.
 */
export type StoredSignInDto =
  | { status: "stored"; login: string }
  | { status: "none" }
  | { status: "unavailable"; reason: string }
  /** Not read yet, or not readable because the client id override is invalid. */
  | { status: "unknown" };

export interface AuthStatus {
  status: JobStatus;
  deviceCode: DeviceCodeInfo | null;
  summary: AuthorizationSummary | null;
  repo: string | null;
  message: string | null;
  storedSignIn: StoredSignInDto;
  /**
   * Set when the latest check is blocked only because the PGARD GitHub App is not installed for
   * this repository (`guidedInstallRemedy`); the panel offers the install link. `null` otherwise.
   */
  remedy: InstallRemedyDto | null;
  /**
   * Set when the latest check is blocked because GitHub showed no repository although the App is
   * installed on the owner account for all repositories. Not a remedy: adding the repository does
   * not apply, so the panel only explains. `null` otherwise.
   */
  accessNote: "app_covers_all_repositories" | null;
  /** Short, secret-free text about the sign-in (reused, saved, removed, signed out). */
  signInNotice: string | null;
  /**
   * Epoch ms after which an allowed check no longer opens port discovery and probes (the server
   * enforces it; this lets the panel say so). `null` unless the latest check is allowed.
   */
  expiresAt: number | null;
  /**
   * Epoch ms until which the server accepts owner-approval re-checks for the offered install
   * (10 minutes from when the check finished). Set only while the panel can wait for an install;
   * the server enforces it, so reloading or remounting the panel never extends the wait.
   */
  installWaitEndsAt: number | null;
}

export interface SignOutRequestDto {
  /** `true` also deletes the sign-in from the OS keychain; otherwise only this dashboard's session ends. */
  removeStored?: boolean;
}

export interface ServiceIdentityDto {
  port: number;
  url: string;
  status: number | null;
  title: string | null;
  inferredTechnologies: string[];
  isHttp: boolean;
  hasUnfollowedRedirect: boolean;
  error: string | null;
}

export interface PortListResponse {
  services: Array<ServiceIdentityDto & { processName: string | null }>;
  isDiscoveryAvailable: boolean;
  note: string | null;
}

export interface TargetInfo {
  port: number;
  origin: string;
  title: string | null;
}

export interface ScanProgressDto {
  stage: string;
  status: string;
  message: string;
}

export interface ScanStatus {
  status: JobStatus | "cancelled";
  scopes: ScanScope[];
  progress: ScanProgressDto[];
  result: ScanResult | null;
  message: string | null;
  /** Set while the GitHub sign-in started by this scan waits for the user. */
  deviceCode: DeviceCodeInfo | null;
}

/** Formats the browser can download from `GET /api/reports/<format>`. */
export type ReportFormatDto = "html" | "pdf";
