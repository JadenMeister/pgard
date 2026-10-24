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
  isClientIdConfigured: boolean;
}

export interface DeviceCodeInfo {
  userCode: string;
  verificationUri: string;
  expiresIn: number;
}

export type JobStatus = "idle" | "running" | "done" | "failed";

export interface AuthStatus {
  status: JobStatus;
  deviceCode: DeviceCodeInfo | null;
  summary: AuthorizationSummary | null;
  repo: string | null;
  message: string | null;
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

export type ReportFormatDto = "html" | "pdf" | "both";

export interface ReportRequestDto {
  format: ReportFormatDto;
  /** Absolute path of an existing directory chosen by the user. */
  outputDir: string;
  isInsideRepositoryConfirmed: boolean;
}

export type ReportResponse =
  { status: "saved"; files: string[] } | { status: "needs_confirmation"; warning: string };
