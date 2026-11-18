/**
 * Helpers for linking model attributes to the views a controller returns (#338): the paths a
 * handler is mapped to, which one answers a GET, and the name a `@ModelAttribute` method gives.
 * Everything here reads annotations and literals only; nothing is evaluated.
 */
import type { Annotation, ClassInfo, Expr, MethodInfo } from "./ir.js";

const MAPPING_ANNOTATIONS = new Set([
  "RequestMapping",
  "GetMapping",
  "PostMapping",
  "PutMapping",
  "DeleteMapping",
  "PatchMapping",
]);
const GET_ANNOTATIONS = new Set(["GetMapping", "GET", "Get"]);

/**
 * String literals of a mapping annotation's value (`"/a"`, `{"/a", "/b"}`, `path = "/a"`); `[""]`
 * when it has none (the class path alone); null when one is not a literal (a constant).
 */
function mappingPaths(annotation: Annotation | undefined): string[] | null {
  if (annotation === undefined) return [""];
  const out: string[] = [];
  let opaque = false;
  const take = (expr: Expr | null | undefined): void => {
    if (expr === null || expr === undefined) return;
    if (expr.k === "str") out.push(expr.text);
    else if (expr.k === "array") for (const elem of expr.elems.slice(0, 20)) take(elem);
    else opaque = true;
  };
  take(annotation.value);
  take(annotation.named.get("path"));
  take(annotation.named.get("value"));
  if (opaque) return null;
  return out.length === 0 ? [""] : out.slice(0, 20);
}

/** A path as a redirect and a mapping compare it: no query, one leading slash, no trailing one. */
export function normalizePath(path: string): string {
  const bare = (path.split(/[?#]/, 1)[0] ?? "").trim().replace(/\/{2,}/g, "/");
  const lead = bare.startsWith("/") ? bare : `/${bare}`;
  return lead.length > 1 ? lead.replace(/\/$/, "") : lead;
}

/** Every path a handler method is reachable under (class prefix, then method path); empty when unknown. */
export function fullPaths(method: MethodInfo, cls: ClassInfo | null): string[] {
  const mapping = method.annotations.find((annotation) => MAPPING_ANNOTATIONS.has(annotation.name));
  const own = mappingPaths(mapping);
  const prefix = mappingPaths(
    cls?.annotations?.find((annotation) => annotation.name === "RequestMapping"),
  );
  if (own === null || prefix === null) return [];
  const out: string[] = [];
  for (const head of prefix) {
    for (const tail of own) {
      if (out.length < 20) out.push(normalizePath(`${head}/${tail}`));
    }
  }
  return out;
}

/** The handler answers a GET (the request a redirect leads to). */
export function answersGet(method: MethodInfo, words: (expr: Expr) => string): boolean {
  for (const annotation of method.annotations) {
    if (GET_ANNOTATIONS.has(annotation.name)) return true;
    if (annotation.name === "RequestMapping") {
      const verbs = annotation.named.get("method");
      return verbs === undefined || /\bGET\b/.test(words(verbs));
    }
  }
  return false;
}

/** A mapping with path variables against a literal redirect target, segment by segment. */
export function matchesTemplate(mapping: string, target: string): boolean {
  const have = mapping.split("/");
  const want = target.split("/");
  if (have.length !== want.length) return false;
  return have.every(
    (segment, i) => segment === want[i] || /^\{.*\}$/.test(segment) || segment === "*",
  );
}

export const isTemplatedPath = (path: string): boolean => /[{*]/.test(path);

const decapitalize = (name: string): string => name.charAt(0).toLowerCase() + name.slice(1);

/** The model attribute name a `@ModelAttribute` method gives (its argument, else from its return type). */
export function modelAttributeName(
  annotation: Annotation,
  returnType: string | null | undefined,
): string | null {
  const explicit = [
    annotation.value,
    annotation.named.get("name"),
    annotation.named.get("value"),
  ].find((expr) => expr?.k === "str");
  if (explicit?.k === "str") return explicit.text;
  const type = (returnType ?? "").replace(/\s/g, "").replace(/\?$/, "");
  const simple = /^(?:[\w.]+\.)?(\w+)$/.exec(type);
  if (simple !== null && !/^(?:void|Unit)$/.test(simple[1] as string)) {
    return decapitalize(simple[1] as string);
  }
  const collection =
    /^(?:[\w.]+\.)?(?:Mutable)?(List|Collection|Set|Iterable)<(?:out)?(?:[\w.]+\.)?(\w+)\??>$/.exec(
      type,
    );
  if (collection !== null) {
    return `${decapitalize(collection[2] as string)}${collection[1] === "Set" ? "Set" : "List"}`;
  }
  return null;
}
