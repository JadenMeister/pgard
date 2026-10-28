# Rule mapping policy

> [한국어](RULE_MAPPING.ko.md) translation available. This English file is the reference; the translation follows it.

Every PGARD rule carries standards mappings in its metadata (`standards` in `packages/findings/src/rule-metadata.ts`): OWASP Top 10:2025 categories, CWE ids and SEI CERT Java rules. They appear in finding references and in the standards views, so they must be accurate. This document says how a mapping is chosen. A test fails when a rule breaks the policy, so the policy cannot drift.

## 1. CWE specificity

Pick the CWE that names the weakness the rule detects.

- Prefer **Base** and **Variant** entries. MITRE calls them "a preferred level of abstraction for mapping to the root causes of vulnerabilities".
- Check the entry's **Vulnerability Mapping Notes** on cwe.mitre.org (CWE 4.20). Usage is `ALLOWED`, `ALLOWED-WITH-REVIEW` or `DISCOURAGED`.
- Avoid a **Pillar** or **Class** entry, and never use one marked `DISCOURAGED`, unless no more specific entry fits. Then keep it and explain why in `standards.mappingNote.discouragedCwe`.
- Do not force a lower-level entry just to reach Base or Variant. MITRE says the same.
- Add a second CWE only when the rule detects a second, distinct weakness (for example a hardcoded key is both CWE-321 and CWE-798).

A Class entry that MITRE does not mark `DISCOURAGED` (for example CWE-327, `ALLOWED-WITH-REVIEW`) needs no `mappingNote`: use it when it is the entry that names the weakness, and the test that pins the Pillar and Class CWEs in use keeps such a choice visible in review. Only `DISCOURAGED` entries need a note.

Every CWE a rule uses must have an entry in `CWE_MAPPING_USAGE` (abstraction and usage as read from MITRE). Adding a CWE to a rule means reading its mapping notes first.

## 2. OWASP category

A rule's `standards.owasp` is **derived from its CWEs**: the set of OWASP Top 10:2025 categories whose "List of Mapped CWEs" contains one of the rule's CWEs. The lists are bundled in `packages/findings/src/standards/owasp-mapped-cwes.ts` (ids only).

- The category does not follow the category's prose, because the prose is open to interpretation and the lists are not. For example, a missing `X-Frame-Options` header reads like a misconfiguration, but CWE-1021 is listed under A06 Insecure Design, so the rule maps to A06.
- A rule with CWEs in two categories lists both. Each OWASP category is then a real mapping of one of the rule's CWEs.
- A rule that departs from this (a category that none of its CWEs maps to, or a missing one) must say why in `standards.mappingNote.owaspDeparture`. Today no rule departs.
- A CWE that is in no OWASP list contributes no category.

## 3. CERT Java `via-cwe` links

SEI CERT Java has no web-rule mappings of its own, so PGARD links a rule to a CERT rule through a CWE (`kind: "via-cwe"`). Keep such a link only when both hold:

1. SEI's "MITRE CWE" related-guidelines table lists the CWE for that CERT rule (`CERT_JAVA_RULES`). SEI states that this table "was provided by outside contributors and has not been verified by SEI CERT".
2. The CERT rule is **topically related** to what the PGARD rule detects.

A sourced but unrelated link is dropped. MSC02-J ("Generate strong random numbers") lists CWE-327, but PG-CRYPTO-003 detects a broken cipher, not weak randomness, so the link was removed.

Use `kind: "direct"` only when the CERT rule is about the rule's weakness itself, and only for a rule that applies to Java or Kotlin. A `direct` entry:

- must name a rule that exists in `CERT_JAVA_RULES` (the SEI **rules**, not its recommendations: MSC61-J is a recommendation and cannot be linked);
- is judged on topic, because the CWE table is incomplete (it lists only CWE-116 for IDS00-J and CWE-171 and CWE-647 for FIO16-J). Where the table lists one of the rule's CWEs, that is further support; where it does not, the entry stays only if the CERT rule's title and text are about the same weakness. `apps/cli/src/rule-standards.test.ts` pins every direct entry and names the topical ones;
- is shown only on findings in `.java` and `.kt` files (`references.cert`, `standardsForPath`). A finding in any other language never shows a direct CERT link.

Every rule that applies to Java or Kotlin has either a `direct` entry or the explicit marker `standards.noDirectCert` (an English and Korean reason why no CERT Java rule is about the weakness); `validateRuleMetadata` rejects a rule with neither, with both, or with either on a rule that does not apply to Java or Kotlin. If you are unsure that a CERT rule is about the weakness, leave it out and use the marker. A mapping is a cross-reference and never a compliance claim.

Presentation (coverage views and the UI): show `via-cwe` as a secondary "Related (via CWE-xxx)" group, never as "Maps to"; always name the bridging CWE and note that SEI has not verified its CWE table; never count it toward CERT coverage.

## 4. `mappingNote`

`standards.mappingNote` is an optional, additive field with one English and Korean text per kind of departure. Each field is required in exactly its case and rejected otherwise, so a note is always a real deviation and a note for one kind cannot excuse the other:

- `owaspDeparture`: the rule's OWASP categories differ from the ones its CWEs map to;
- `discouragedCwe`: the rule keeps a CWE that MITRE marks `DISCOURAGED`.

The two rules that keep CWE-693 (a Pillar, `DISCOURAGED`) carry a `discouragedCwe` note: PG-WEB-001 (Content-Security-Policy) and PG-WEB-003 (`nosniff`). No specific CWE describes a missing header of that kind.

## 5. Enforcement

- `validateRuleMetadata` (used by the tests) reports a rule whose OWASP categories do not match its CWEs without a `mappingNote.owaspDeparture`, a `DISCOURAGED` CWE without a `mappingNote.discouragedCwe`, an unneeded note, duplicate OWASP ids, and a CWE with no recorded mapping usage.
- `apps/cli/src/rule-standards.test.ts` pins the exceptions: which rules carry a note, which Pillar and Class CWEs are used, and which CERT links exist.
- `packages/findings/src/standards/standards.test.ts` checks the bundled lists. Regenerate them with `packages/findings/scripts/generate-owasp-mapped-cwes.mjs` and review the diff.

## Sources

- OWASP Top 10:2025 category pages, "List of Mapped CWEs": https://top10.owasp.org/2025/ (CC BY-SA 4.0 per the document's own licence section).
- CWE definitions and their Vulnerability Mapping Notes: https://cwe.mitre.org/ (MITRE CWE Terms of Use).
- SEI CERT Oracle Coding Standard for Java and its "MITRE CWE" table: https://cmu-sei.github.io/secure-coding-standards/ (CC BY 4.0).

Only identifiers, abstraction levels and usage labels are bundled. See [NOTICE.md](../NOTICE.md) for licences and attribution.
