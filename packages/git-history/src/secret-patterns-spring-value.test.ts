import { describe, expect, it } from "vitest";
import { detectSecrets } from "./secret-patterns.js";

/**
 * #350: a `spring.datasource.password` default is no longer a PG-CRYPTO-002 "cryptographic key".
 * The hardcoded credential must still be reported by the secret rules, so nothing is lost.
 */
describe("Spring @Value password defaults stay visible to the secret rules", () => {
  it.each([
    "spring.datasource.password:s3cretPassw0rd",
    "spring.redis.password:Rd1s-Pr0d-Pass",
    "spring.mail.password:Sm7p-Pr0d-Pass",
  ])("reports the literal default of %s", (placeholder) => {
    const found = detectSecrets(`@Value("\${${placeholder}}") String password;`, {
      path: "A.java",
    });
    expect(found.map((secret) => secret.kind)).toContain("generic_credential");
  });
});
