# Documents in `docs/`

Back to the project [README](../README.md) ([한국어](../README.ko.md)).

The README and `RESULT_SCHEMA.md` describe what PGARD does today. The three Korean planning documents are the record of the MVP plan, written before and during implementation. Where a planning document differs from the README (for example, the planning documents mention an advisory database, which PGARD does not have), the README and the code are correct.

| Document                                                                     | Role                                                                                | Language | Status                                                                         |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------ |
| [`RESULT_SCHEMA.md`](RESULT_SCHEMA.md)                                       | How the scan result schema is versioned and how a reader treats another version     | English  | Current policy                                                                 |
| [`PGARD_AGENT_BRIEF_KO.md`](PGARD_AGENT_BRIEF_KO.md)                         | Implementation brief: product scope, authorization gate, scan boundaries, done list | Korean   | Historical MVP planning record                                                 |
| [`PGARD_CLI_AND_STRUCTURE_KO.md`](PGARD_CLI_AND_STRUCTURE_KO.md)             | Command set and the layout of the apps and packages                                 | Korean   | Historical MVP planning record                                                 |
| [`PGARD_DEVELOPMENT_CONVENTIONS_KO.md`](PGARD_DEVELOPMENT_CONVENTIONS_KO.md) | Commit units and messages, naming, verification and pull request rules              | Korean   | Historical MVP planning record; also the reference for development conventions |

For the policies themselves (authorization, privacy, credentials, redaction, dashboard security, web checks, out of scope), see [Policies](../README.md#policies) in the README ([한국어](../README.ko.md#정책)).
