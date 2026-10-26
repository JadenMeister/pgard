import type { CweTop25Entry, StandardProvenance } from "./types.js";

export const CWE_TOP25_PROVENANCE: StandardProvenance = {
  name: "CWE Top 25 Most Dangerous Software Weaknesses",
  edition: "2025",
  sourceUrl: "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
  retrievedAt: "2026-10-26",
  license: "MITRE CWE Terms of Use (free use with copyright notice)",
  attribution: "(c) 2006-2026 The MITRE Corporation. CWE is a trademark of The MITRE Corporation.",
};

const entry = (rank: number, num: number, name: string): CweTop25Entry => ({
  rank,
  id: `CWE-${num}`,
  name,
  url: `https://cwe.mitre.org/data/definitions/${num}.html`,
});

export const CWE_TOP25: readonly CweTop25Entry[] = [
  entry(
    1,
    79,
    "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  ),
  entry(
    2,
    89,
    "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  ),
  entry(3, 352, "Cross-Site Request Forgery (CSRF)"),
  entry(4, 862, "Missing Authorization"),
  entry(5, 787, "Out-of-bounds Write"),
  entry(6, 22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
  entry(7, 416, "Use After Free"),
  entry(8, 125, "Out-of-bounds Read"),
  entry(
    9,
    78,
    "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  ),
  entry(10, 94, "Improper Control of Generation of Code ('Code Injection')"),
  entry(11, 120, "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"),
  entry(12, 434, "Unrestricted Upload of File with Dangerous Type"),
  entry(13, 476, "NULL Pointer Dereference"),
  entry(14, 121, "Stack-based Buffer Overflow"),
  entry(15, 502, "Deserialization of Untrusted Data"),
  entry(16, 122, "Heap-based Buffer Overflow"),
  entry(17, 863, "Incorrect Authorization"),
  entry(18, 20, "Improper Input Validation"),
  entry(19, 284, "Improper Access Control"),
  entry(20, 200, "Exposure of Sensitive Information to an Unauthorized Actor"),
  entry(21, 306, "Missing Authentication for Critical Function"),
  entry(22, 918, "Server-Side Request Forgery (SSRF)"),
  entry(
    23,
    77,
    "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
  ),
  entry(24, 639, "Authorization Bypass Through User-Controlled Key"),
  entry(25, 770, "Allocation of Resources Without Limits or Throttling"),
];
