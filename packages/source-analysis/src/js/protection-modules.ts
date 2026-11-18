/** Libraries whose import counts as CSRF protection (used by the project-wide heuristics). */
export const CSRF_MODULES = [
  "csurf",
  "csrf-csrf",
  "csrf-sync",
  "lusca",
  "tiny-csrf",
  "@fastify/csrf-protection",
  "@nestjs/csrf",
  "csrf",
];

/** Libraries whose import counts as rate limiting (used by the project-wide heuristics). */
export const RATE_LIMIT_MODULES = [
  "express-rate-limit",
  "rate-limiter-flexible",
  "express-brute",
  "express-slow-down",
  "@nestjs/throttler",
  "@fastify/rate-limit",
  "limiter",
  "bottleneck",
  "hono-rate-limiter",
];

/** True when `name` is one of the candidate modules or a sub-path of one. */
export function isModuleOf(name: string, candidates: readonly string[]): boolean {
  return candidates.some((candidate) => name === candidate || name.startsWith(`${candidate}/`));
}
