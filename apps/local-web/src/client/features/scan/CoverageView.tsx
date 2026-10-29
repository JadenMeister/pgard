import type { ScanResult } from "@pgard/findings";
import type { ScanStatus } from "../../../shared/api-types";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import { AdvisoryStatusLine } from "./AdvisoryStatusLine";
import { ConfigNotices } from "./ConfigNotices";
import { CoverageTable } from "./CoverageTable";
import { ActivityLog } from "./ScanProgress";
import { SuppressionNotices } from "./SuppressionNotices";

/** The Coverage view: what ran and what did not, the config's effect, and the progress log. */
export function CoverageView({ scan, result }: { scan: ScanStatus; result: ScanResult }) {
  const { m } = useI18n();
  return (
    <Section title={m.nav.coverage}>
      <AdvisoryStatusLine />
      <ConfigNotices coverage={result.coverage} />
      <SuppressionNotices result={result} />
      <CoverageTable coverage={result.coverage} />
      <ActivityLog events={scan.progress} />
    </Section>
  );
}
