import { sanitizeDisplayText } from "./display-text.js";

/**
 * Does a local web service look like it belongs to the project? A heuristic over signals the
 * identity probe already collected (title, headers, guessed technology) and local project facts
 * (names and declared dependencies). It never makes a request, never blocks anything and a match
 * is never proof: the user's `y` stays the only confirmation.
 */
export type RelatednessVerdict = "likely" | "unclear" | "unlikely";

/** What the existing identity `GET /` already returned. No body is kept. */
export interface ServiceSignals {
  title: string | null;
  /** `ServiceIdentity.inferredTechnologies`: Server / X-Powered-By / generator and markers. */
  technologies: readonly string[];
}

/** Local, read-only facts about the project (see `readProjectSignals`). */
export interface ProjectSignals {
  /** Last segment of the project folder. */
  folderName: string | null;
  /** Verified GitHub `owner/name`, when the gate resolved it. */
  repo: string | null;
  /** `name` of package.json, pyproject.toml, composer.json; module name of go.mod. */
  manifestNames: readonly string[];
  /** Lower-case names of declared dependencies (any ecosystem). */
  dependencies: readonly string[];
}

export type RelatednessReason =
  | { kind: "name"; token: string }
  | { kind: "framework"; framework: string }
  | { kind: "mismatch"; service: string; project: string }
  | { kind: "known-tool"; tool: string };

export interface Relatedness {
  verdict: RelatednessVerdict;
  reasons: RelatednessReason[];
  /** Short, sanitized and length-capped; safe to show. `null` when there is nothing to name. */
  serviceLabel: string | null;
  projectLabel: string | null;
}

export const RELATEDNESS_LABEL_MAX = 40;
const INPUT_MAX = 300;
const MAX_ENTRIES = 200;
const MAX_DEPENDENCIES = 5000;
const MIN_TOKEN_LENGTH = 3;

export const EMPTY_PROJECT_SIGNALS: ProjectSignals = {
  folderName: null,
  repo: null,
  manifestNames: [],
  dependencies: [],
};

/** Words that name a kind of thing, not a project; they must not make two things "the same". */
const GENERIC_TOKENS = new Set([
  "app",
  "web",
  "api",
  "www",
  "the",
  "and",
  "dev",
  "server",
  "client",
  "frontend",
  "backend",
  "site",
  "project",
  "test",
  "tests",
  "demo",
  "example",
  "examples",
  "sample",
  "starter",
  "template",
  "localhost",
  "local",
  "admin",
  "service",
  "services",
  "main",
  "src",
  "dashboard",
  "console",
  "panel",
  "portal",
  "home",
  "login",
  "index",
  "welcome",
  "docs",
  "node",
  "npm",
  "html",
  "page",
  "error",
  "not",
  "found",
  "http",
  "https",
  "running",
]);

/** Case-folded name tokens (split on `-`, `_`, space, `.`, camelCase), 3+ characters, no filler. */
export function nameTokens(value: string): string[] {
  const text = sanitizeDisplayText(value, INPUT_MAX)
    .normalize("NFKC")
    .replace(/(\p{Ll})(\p{Lu})/gu, "$1 $2");
  const tokens = new Set<string>();
  for (const part of text.toLowerCase().split(/[^\p{L}\p{N}]+/u)) {
    if ([...part].length < MIN_TOKEN_LENGTH || GENERIC_TOKENS.has(part)) continue;
    if (/^[0-9]+$/.test(part)) continue;
    tokens.add(part);
  }
  return [...tokens];
}

// --- Frameworks ----------------------------------------------------------------------------

/** Server-side or meta frameworks: only these can make a clear mismatch. */
const SERVER_FRAMEWORKS = new Set([
  "next",
  "nuxt",
  "express",
  "nest",
  "fastify",
  "django",
  "flask",
  "fastapi",
  "laravel",
  "symfony",
  "spring-boot",
  "gin",
  "echo",
  "rails",
]);

const FRAMEWORK_NAMES: Record<string, string> = {
  next: "Next.js",
  nuxt: "Nuxt",
  vite: "Vite",
  react: "React",
  vue: "Vue",
  svelte: "Svelte",
  express: "Express",
  nest: "NestJS",
  fastify: "Fastify",
  django: "Django",
  flask: "Flask",
  fastapi: "FastAPI",
  laravel: "Laravel",
  symfony: "Symfony",
  "spring-boot": "Spring Boot",
  gin: "Gin",
  echo: "Echo",
  rails: "Rails",
};

/** Declared dependency name (lower case) to the framework it means. */
const DEPENDENCY_FRAMEWORKS: Array<[RegExp, string]> = [
  [/^next$/, "next"],
  [/^nuxt3?$|^@nuxt\//, "nuxt"],
  [/^vite$/, "vite"],
  [/^react$/, "react"],
  [/^vue$/, "vue"],
  [/^svelte$|^@sveltejs\/kit$/, "svelte"],
  [/^express$/, "express"],
  [/^@nestjs\/core$/, "nest"],
  [/^fastify$/, "fastify"],
  [/^django$/, "django"],
  [/^flask$/, "flask"],
  [/^fastapi$/, "fastapi"],
  [/^laravel\/framework$/, "laravel"],
  [/^symfony\/(framework-bundle|symfony)$/, "symfony"],
  [/^org\.springframework\.boot$|^spring-boot(-starter.*)?$/, "spring-boot"],
  [/^github\.com\/gin-gonic\/gin$/, "gin"],
  [/^github\.com\/labstack\/echo(\/v[0-9]+)?$/, "echo"],
  [/^rails$/, "rails"],
];

/** A framework that is built on others also counts as them. */
const IMPLIES: Record<string, string[]> = {
  next: ["react"],
  nuxt: ["vue"],
  nest: ["express", "fastify"],
  svelte: ["vite"],
};

function projectFrameworks(dependencies: readonly string[]): Set<string> {
  const found = new Set<string>();
  for (const dependency of dependencies) {
    for (const [pattern, framework] of DEPENDENCY_FRAMEWORKS) {
      if (pattern.test(dependency)) found.add(framework);
    }
  }
  for (const framework of [...found]) {
    for (const implied of IMPLIES[framework] ?? []) found.add(implied);
  }
  return found;
}

/** Patterns over the service's title and technology guesses. */
const SERVICE_FRAMEWORK_PATTERNS: Array<[RegExp, string]> = [
  [/next\.?js/, "next"],
  [/nuxt/, "nuxt"],
  [/\bvite\b/, "vite"],
  [/\breact\b/, "react"],
  [/\bvue(\.js)?\b/, "vue"],
  [/svelte/, "svelte"],
  [/\bexpress\b/, "express"],
  [/\bnest\.?js\b/, "nest"],
  [/fastify/, "fastify"],
  [/django/, "django"],
  [/flask|werkzeug/, "flask"],
  [/fastapi|uvicorn|starlette/, "fastapi"],
  [/laravel/, "laravel"],
  [/symfony/, "symfony"],
  [/spring boot|whitelabel error page/, "spring-boot"],
  [/ruby on rails|\brails\b/, "rails"],
];

/** Server software that only names a language: it matches any framework of that language. */
const SERVICE_FAMILIES: Array<[RegExp, string, string[]]> = [
  [/\bphp\b/, "PHP", ["laravel", "symfony"]],
  [/gunicorn|wsgiserver|cpython|\bpython\b/, "Python", ["django", "flask", "fastapi"]],
];

// --- Known unrelated tools -------------------------------------------------------------------

interface KnownTool {
  name: string;
  pattern: RegExp;
  /** A declared dependency containing one of these means the project works with the tool. */
  dependencies: string[];
}

const KNOWN_TOOLS: KnownTool[] = [
  { name: "Grafana", pattern: /grafana/, dependencies: ["grafana"] },
  {
    name: "Jupyter",
    pattern: /jupyter|ipython notebook/,
    dependencies: ["jupyter", "notebook", "ipykernel", "ipywidgets", "nbformat"],
  },
  { name: "pgAdmin", pattern: /pgadmin/, dependencies: ["pgadmin"] },
  { name: "Docker Desktop", pattern: /docker desktop/, dependencies: ["docker"] },
  { name: "Ollama", pattern: /ollama/, dependencies: ["ollama"] },
  { name: "LM Studio", pattern: /lm[ -]?studio/, dependencies: ["lmstudio", "lm-studio"] },
  { name: "Adminer", pattern: /adminer/, dependencies: ["adminer"] },
  { name: "phpMyAdmin", pattern: /phpmyadmin/, dependencies: ["phpmyadmin"] },
  { name: "Mongo Express", pattern: /mongo[ -]express/, dependencies: ["mongo-express"] },
  { name: "RedisInsight", pattern: /redis ?insight/, dependencies: ["redisinsight"] },
  { name: "Redis Commander", pattern: /redis commander/, dependencies: ["redis-commander"] },
  { name: "Kubernetes Dashboard", pattern: /kubernetes dashboard/, dependencies: ["kubernetes"] },
  { name: "Portainer", pattern: /portainer/, dependencies: ["portainer"] },
  { name: "Prometheus", pattern: /prometheus/, dependencies: ["prometheus", "prom-client"] },
  { name: "Kibana", pattern: /kibana/, dependencies: ["kibana"] },
  {
    name: "RabbitMQ Management",
    pattern: /rabbitmq management/,
    dependencies: ["rabbitmq", "amqp"],
  },
  { name: "MinIO Console", pattern: /minio (console|browser)/, dependencies: ["minio"] },
];

/** Names of the tools that count as "known unrelated" (for docs and tests). */
export const KNOWN_TOOL_NAMES: readonly string[] = KNOWN_TOOLS.map((tool) => tool.name);

// --- Verdict ---------------------------------------------------------------------------------

function cap(value: string | null): string | null {
  if (value === null) return null;
  const cleaned = sanitizeDisplayText(value, RELATEDNESS_LABEL_MAX);
  return cleaned === "" ? null : cleaned;
}

function repoName(project: ProjectSignals): string | null {
  return project.repo === null ? null : (project.repo.split("/").pop() ?? null);
}

function hasAnySignal(project: ProjectSignals): boolean {
  return (
    project.folderName !== null ||
    project.repo !== null ||
    project.manifestNames.length > 0 ||
    project.dependencies.length > 0
  );
}

export function relatedness(service: ServiceSignals, project: ProjectSignals): Relatedness {
  const projectLabel = cap(
    project.folderName ?? repoName(project) ?? project.manifestNames[0] ?? null,
  );
  const title = service.title === null ? null : sanitizeDisplayText(service.title, INPUT_MAX);
  const technologies = service.technologies
    .slice(0, MAX_ENTRIES)
    .map((entry) => sanitizeDisplayText(entry, INPUT_MAX))
    .filter((entry) => entry !== "");
  const result = (
    verdict: RelatednessVerdict,
    reasons: RelatednessReason[],
    serviceLabel: string | null,
  ): Relatedness => ({ verdict, reasons, serviceLabel: cap(serviceLabel), projectLabel });
  const fallbackLabel = title ?? technologies[0] ?? null;
  if (!hasAnySignal(project) || (title === null && technologies.length === 0)) {
    return result("unclear", [], fallbackLabel);
  }
  const serviceText = [title ?? "", ...technologies].join("\n");
  const haystack = serviceText.normalize("NFKC").toLowerCase();

  // 1. A project name word in the title or headers.
  const projectTokens = new Set<string>();
  for (const source of [
    project.folderName,
    repoName(project),
    ...project.manifestNames.slice(0, MAX_ENTRIES),
  ]) {
    if (source !== null) for (const token of nameTokens(source)) projectTokens.add(token);
  }
  const serviceTokens = new Set(nameTokens(serviceText));
  for (const token of projectTokens) {
    if (serviceTokens.has(token)) {
      return result("likely", [{ kind: "name", token }], fallbackLabel);
    }
  }

  // 2. A known tool the project does not work with.
  const dependencies = project.dependencies
    .slice(0, MAX_DEPENDENCIES)
    .map((entry) => entry.toLowerCase());
  const tool = KNOWN_TOOLS.find((candidate) => candidate.pattern.test(haystack));
  if (tool !== undefined) {
    const isUsed = dependencies.some((dependency) =>
      tool.dependencies.some((hint) => dependency.includes(hint)),
    );
    if (!isUsed) return result("unlikely", [{ kind: "known-tool", tool: tool.name }], tool.name);
  }

  // 3. Frameworks: the service's technology against what the project declares.
  const projectSet = projectFrameworks(dependencies);
  const serviceIds = SERVICE_FRAMEWORK_PATTERNS.filter(([pattern]) => pattern.test(haystack)).map(
    ([, id]) => id,
  );
  // A language only counts when nothing more specific was recognised (Werkzeug is Flask, not any
  // Python framework).
  const families =
    serviceIds.length > 0 ? [] : SERVICE_FAMILIES.filter(([pattern]) => pattern.test(haystack));
  const matched =
    serviceIds.find((id) => projectSet.has(id)) ??
    families.flatMap(([, , members]) => members).find((id) => projectSet.has(id));
  if (matched !== undefined) {
    return result("likely", [{ kind: "framework", framework: matched }], fallbackLabel);
  }
  // A clear mismatch needs a server framework on both sides and nothing in common.
  const projectServer = [...projectSet].find((id) => SERVER_FRAMEWORKS.has(id));
  const serviceServer = serviceIds.find((id) => SERVER_FRAMEWORKS.has(id));
  const serviceName =
    serviceServer === undefined
      ? families[0]?.[1]
      : (FRAMEWORK_NAMES[serviceServer] ?? serviceServer);
  if (projectServer !== undefined && serviceName !== undefined) {
    return result(
      "unlikely",
      [
        {
          kind: "mismatch",
          service: serviceName,
          project: FRAMEWORK_NAMES[projectServer] ?? projectServer,
        },
      ],
      title ?? serviceName,
    );
  }
  return result("unclear", [], fallbackLabel);
}
