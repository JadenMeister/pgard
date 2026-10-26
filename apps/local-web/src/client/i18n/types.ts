import type { en } from "./en";

/** Replaces every literal string in `T` with `string`, keeping keys, tuple lengths and function shapes. */
type Widen<T> = T extends string
  ? string
  : T extends (...args: infer A) => infer R
    ? (...args: A) => R
    : { [K in keyof T]: Widen<T[K]> };

/** The shape both catalogs must have. A key missing from (or extra in) `ko.ts` fails typecheck. */
export type Messages = Widen<typeof en>;

export type Language = "ko" | "en";
