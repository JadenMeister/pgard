import { redactLocationPath } from "@pgard/findings";
import type { Dependency, DependencyCollection, DependencyCoverage } from "./types.js";

/**
 * A CycloneDX 1.6 JSON SBOM built from what the lockfile parsers already returned. Nothing here
 * reads a file, runs a tool or uses the network: it is a pure function of its input, so the same
 * input always gives the same document (the caller supplies the clock and the serial number).
 */

export const CYCLONEDX_SPEC_VERSION = "1.6";
export const SBOM_FORMAT = "cyclonedx-json";

/** OSV ecosystem names. Only npm and Go are parsed today; the purl rules cover the next ones. */
export type SbomEcosystem = Dependency["ecosystem"] | "Maven" | "PyPI" | "Packagist";

/** The part of a dependency the SBOM uses. */
export interface SbomDependency {
  ecosystem: SbomEcosystem;
  name: string;
  version: string;
  direct?: boolean | undefined;
  path: string;
}

/** Characters purl leaves as they are (RFC 3986 unreserved). Everything else is %-encoded. */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

const encodePath = (segments: readonly string[]): string => segments.map(encodeSegment).join("/");

/**
 * The Package URL of a package, or `null` when the name does not fit its ecosystem.
 *
 * - npm: `pkg:npm/%40scope/name@1.0.0`. The `@` of a scope is %-encoded, as the purl spec says.
 * - Go: `pkg:golang/github.com/Azure/azure-sdk-for-go@v1.2.3`. The module path keeps its case:
 *   Go module paths are case-sensitive and OSV, syft and Dependency-Track keep it, so a lowercased
 *   path would be a different module. The `!x` escaping is only for the module proxy's URLs and
 *   is not purl syntax. `+incompatible` becomes `%2Bincompatible`.
 * - Maven: `group:artifact` becomes `pkg:maven/group/artifact@1.0`.
 * - PyPI: lowercase, with `_` and `.` turned into `-` (the spec's normalisation).
 * - Composer (OSV "Packagist"): lowercase `vendor/name`.
 */
const isDotSegment = (part: string): boolean => part === "." || part === "..";

export function purlFor(ecosystem: SbomEcosystem, name: string, version: string): string | null {
  if (name === "" || version === "") return null;
  // A dot segment would turn the purl into a path that points somewhere else.
  if (name.split(/[/:]/).some(isDotSegment)) return null;
  const suffix = `@${encodeSegment(version)}`;
  switch (ecosystem) {
    case "npm": {
      // npm names are kept in their original case on purpose: new packages must be lowercase,
      // but older ones are not, and the registry and OSV match the name as published.
      const parts = name.startsWith("@") ? name.split("/") : [name];
      if (name.startsWith("@") && (parts.length !== 2 || parts[0] === "@" || parts[1] === "")) {
        return null;
      }
      return `pkg:npm/${encodePath(parts)}${suffix}`;
    }
    case "Go": {
      const parts = name.split("/");
      if (parts.some((part) => part === "")) return null;
      return `pkg:golang/${encodePath(parts)}${suffix}`;
    }
    case "Maven": {
      const parts = name.split(":");
      if (parts.length !== 2 || parts.some((part) => part === "")) return null;
      return `pkg:maven/${encodePath(parts)}${suffix}`;
    }
    case "PyPI": {
      const normalized = name.toLowerCase().replace(/[-_.]+/g, "-");
      return normalized === "" ? null : `pkg:pypi/${encodeSegment(normalized)}${suffix}`;
    }
    case "Packagist": {
      const parts = name.toLowerCase().split("/");
      if (parts.length !== 2 || parts.some((part) => part === "")) return null;
      return `pkg:composer/${encodePath(parts)}${suffix}`;
    }
  }
}

/** CycloneDX `group` and `name` for a package (scope or Maven group split off the name). */
function groupAndName(ecosystem: SbomEcosystem, name: string): { group?: string; name: string } {
  if (ecosystem === "npm" && name.startsWith("@") && name.includes("/")) {
    const slash = name.indexOf("/");
    return { group: name.slice(0, slash), name: name.slice(slash + 1) };
  }
  if (ecosystem === "Maven" && name.includes(":")) {
    const colon = name.indexOf(":");
    return { group: name.slice(0, colon), name: name.slice(colon + 1) };
  }
  if (ecosystem === "Packagist" && name.includes("/")) {
    const slash = name.indexOf("/");
    return { group: name.slice(0, slash), name: name.slice(slash + 1) };
  }
  return { name };
}

export interface CycloneDxProperty {
  name: string;
  value: string;
}

export interface CycloneDxComponent {
  type: "library" | "application";
  "bom-ref": string;
  group?: string;
  name: string;
  version?: string;
  purl?: string;
  properties?: CycloneDxProperty[];
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: typeof CYCLONEDX_SPEC_VERSION;
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: { components: { type: "application"; name: string; version: string }[] };
    component: CycloneDxComponent;
    properties: CycloneDxProperty[];
  };
  components: CycloneDxComponent[];
  dependencies: { ref: string; dependsOn: string[] }[];
  compositions?: { aggregate: "incomplete"; assemblies: string[] }[];
}

export interface BuildSbomOptions {
  /** `urn:uuid:...`, unique per document. */
  serialNumber: string;
  /** ISO 8601 UTC time of the export. */
  timestamp: string;
  toolVersion: string;
  /** The repository (`owner/name`), as the authorization check confirmed it. */
  repository: string;
  /** The commit the lockfiles were read at, when known. */
  revision: string | null;
}

/** Coverage statuses that mean the SBOM does not hold everything of that file. */
const INCOMPLETE_STATUSES: ReadonlySet<DependencyCoverage["status"]> = new Set([
  "partial",
  "failed",
  "too-large",
  "not-read",
  "unsupported",
  "missing-lockfile",
]);

export const ROOT_REF = "pgard:repository";

/** Code-unit order: the same on every platform and locale. */
const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Anything that came out of a lockfile or a path is run through the redaction rules first: a
 * secret-looking value is masked, an absolute path is dropped, control, zero-width and bidi
 * characters become visible `\uXXXX` text.
 */
function clean(value: string): string {
  return redactLocationPath(value.slice(0, 500)) ?? "<redacted>";
}

/** The SBOM of the dependencies and coverage `collectDependencies` returned. */
export function buildCycloneDxSbom(
  collection: Pick<DependencyCollection, "coverage" | "isTruncated"> & {
    dependencies: readonly SbomDependency[];
  },
  options: BuildSbomOptions,
): CycloneDxBom {
  interface Entry {
    component: CycloneDxComponent;
    lockfiles: Set<string>;
    isDirect: boolean | undefined;
  }
  const entries = new Map<string, Entry>();
  for (const dependency of collection.dependencies) {
    const name = clean(dependency.name);
    const version = clean(dependency.version);
    const purl = purlFor(dependency.ecosystem, name, version);
    // A package whose name does not fit its ecosystem still appears, under a ref that cannot
    // collide with a purl.
    const ref = purl ?? `pgard:${dependency.ecosystem}:${name}@${version}`;
    let entry = entries.get(ref);
    if (entry === undefined) {
      entry = {
        component: {
          type: "library",
          "bom-ref": ref,
          ...groupAndName(dependency.ecosystem, name),
          version,
          ...(purl === null ? {} : { purl }),
        },
        lockfiles: new Set(),
        isDirect: undefined,
      };
      entry.component.properties = [{ name: "pgard:ecosystem", value: dependency.ecosystem }];
      entries.set(ref, entry);
    }
    entry.lockfiles.add(clean(dependency.path));
    if (dependency.direct === true) entry.isDirect = true;
    else if (dependency.direct === false && entry.isDirect === undefined) entry.isDirect = false;
  }

  const sorted = [...entries.entries()].sort(([a], [b]) => compareText(a, b));
  const components: CycloneDxComponent[] = [];
  const directRefs: string[] = [];
  for (const [ref, entry] of sorted) {
    const properties = entry.component.properties ?? [];
    for (const lockfile of [...entry.lockfiles].sort(compareText)) {
      properties.push({ name: "pgard:lockfile", value: lockfile });
    }
    if (entry.isDirect !== undefined) {
      properties.push({ name: "pgard:direct", value: String(entry.isDirect) });
    }
    if (entry.isDirect === true) directRefs.push(ref);
    components.push({ ...entry.component, properties });
  }

  const unparsed = collection.coverage
    .filter((line) => INCOMPLETE_STATUSES.has(line.status))
    .map((line) => `${clean(line.path)} (${line.status})`)
    .sort(compareText);
  const isIncomplete = unparsed.length > 0 || collection.isTruncated;
  const metadataProperties: CycloneDxProperty[] = [
    // PGARD's parsers return package versions only: they do not read the dev scope or the
    // edges between packages that some lockfiles record.
    { name: "pgard:dependency-graph", value: "direct-only" },
    { name: "pgard:complete", value: String(!isIncomplete) },
    ...(collection.isTruncated ? [{ name: "pgard:truncated", value: "true" }] : []),
    ...unparsed.map((value) => ({ name: "pgard:unparsed-lockfile", value })),
  ];

  const repository = clean(options.repository);
  return {
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: options.serialNumber,
    version: 1,
    metadata: {
      timestamp: options.timestamp,
      tools: {
        components: [{ type: "application", name: "pgard", version: options.toolVersion }],
      },
      component: {
        type: "application",
        "bom-ref": ROOT_REF,
        name: repository,
        ...(options.revision === null ? {} : { version: clean(options.revision) }),
      },
      properties: metadataProperties,
    },
    components,
    // Only the root's direct dependencies are known. A component without an entry has unknown
    // dependencies (an entry with an empty list would claim it has none).
    dependencies: [{ ref: ROOT_REF, dependsOn: directRefs }],
    ...(isIncomplete
      ? { compositions: [{ aggregate: "incomplete" as const, assemblies: [ROOT_REF] }] }
      : {}),
  };
}
