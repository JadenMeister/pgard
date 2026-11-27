export interface FamilyEntry {
  family: string;
  cwes: readonly number[];
  assumed?: readonly number[];
  prefixes: readonly string[];
}
export const FAMILIES: ReadonlyArray<FamilyEntry>;
export const IN_SCOPE_CWES: number[];
export function cweNumber(cwe: string): number;
export function familiesForCwes(cwes: string[]): FamilyEntry[];
export function ruleInFamily(ruleId: string, family: FamilyEntry): boolean;
