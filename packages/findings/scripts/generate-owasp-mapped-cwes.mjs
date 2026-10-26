// Regenerates the CWE lists in src/standards/owasp-mapped-cwes.ts from the "List of Mapped CWEs"
// section of each OWASP Top 10:2025 category page. Run manually (network access needed); the
// output is the body of `OWASP_MAPPED_CWES`, then `npx prettier --write` the file:
//   node packages/findings/scripts/generate-owasp-mapped-cwes.mjs
// Only CWE ids are extracted. The list entries are the `<p>` or `<li>` items that link to
// cwe.mitre.org; CWE ids that appear only in a category's prose are not part of the list.
const PAGES = [
  "A01_2025-Broken_Access_Control",
  "A02_2025-Security_Misconfiguration",
  "A03_2025-Software_Supply_Chain_Failures",
  "A04_2025-Cryptographic_Failures",
  "A05_2025-Injection",
  "A06_2025-Insecure_Design",
  "A07_2025-Authentication_Failures",
  "A08_2025-Software_or_Data_Integrity_Failures",
  "A09_2025-Security_Logging_and_Alerting_Failures",
  "A10_2025-Mishandling_of_Exceptional_Conditions",
];

const lists = {};
for (const page of PAGES) {
  const response = await fetch(`https://top10.owasp.org/2025/${page}/`);
  if (!response.ok) throw new Error(`${response.status} ${page}`);
  const html = await response.text();
  const ids = [
    ...html.matchAll(
      /<(?:p|li)><a href="https:\/\/cwe\.mitre\.org\/data\/definitions\/(\d+)\.html">CWE-\1\b/g,
    ),
  ].map((match) => Number(match[1]));
  lists[`${page.slice(0, 3)}:2025`] = [...new Set(ids)].sort((a, b) => a - b);
}
// Prints the body of `OWASP_MAPPED_CWES`: paste these lines between its braces, then run prettier.
for (const [category, ids] of Object.entries(lists)) {
  console.log(`  "${category}": [${ids.map((id) => `"CWE-${id}"`).join(", ")}],`);
}
