import type { OwaspCategory, StandardProvenance } from "./types.js";

export const OWASP_TOP10_2025_PROVENANCE: StandardProvenance = {
  name: "OWASP Top 10",
  edition: "2025",
  sourceUrl: "https://top10.owasp.org/2025",
  retrievedAt: "2026-10-26",
  license: "Creative Commons Attribution 3.0 Unported (CC BY 3.0)",
  attribution: "OWASP Top 10:2025, (c) OWASP Foundation, https://owasp.org/Top10/",
};

const BASE = "https://top10.owasp.org/2025/";

const category = (id: string, title: string, slug: string): OwaspCategory => ({
  id,
  title,
  url: `${BASE}${slug}/`,
});

export const OWASP_TOP10_2025: readonly OwaspCategory[] = [
  category("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
  category("A02:2025", "Security Misconfiguration", "A02_2025-Security_Misconfiguration"),
  category("A03:2025", "Software Supply Chain Failures", "A03_2025-Software_Supply_Chain_Failures"),
  category("A04:2025", "Cryptographic Failures", "A04_2025-Cryptographic_Failures"),
  category("A05:2025", "Injection", "A05_2025-Injection"),
  category("A06:2025", "Insecure Design", "A06_2025-Insecure_Design"),
  category("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures"),
  category(
    "A08:2025",
    "Software or Data Integrity Failures",
    "A08_2025-Software_or_Data_Integrity_Failures",
  ),
  category(
    "A09:2025",
    "Security Logging and Alerting Failures",
    "A09_2025-Security_Logging_and_Alerting_Failures",
  ),
  category(
    "A10:2025",
    "Mishandling of Exceptional Conditions",
    "A10_2025-Mishandling_of_Exceptional_Conditions",
  ),
];
