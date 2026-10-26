import { baselineNotices, suppressionNotices, type ScanResult } from "@pgard/findings";
import { Notice } from "../../components/ui/Card";
import { useI18n } from "../../i18n/I18nProvider";

/**
 * What the suppressions of pgard.config.json did to this scan (critical findings suppressed,
 * wildcard, broad or expired entries) and whether the baseline is incomplete. The framing is
 * translated; entry names and reasons are shown as written in the file.
 */
export function SuppressionNotices({ result }: { result: ScanResult }) {
  const { m } = useI18n();
  const text = m.scan.suppressionNotice;
  return (
    <>
      {suppressionNotices(result).map((notice) => (
        <Notice key={`${notice.kind}:${notice.text}`} tone="warning">
          {notice.kind === "critical"
            ? text.critical(notice.count ?? 0)
            : notice.kind === "everything"
              ? text.everything(notice.count ?? 0)
              : notice.kind === "incomplete"
                ? text.incomplete
                : notice.kind === "expired"
                  ? text.expired(notice.ruleId ?? "", notice.path ?? "", notice.expires ?? "?")
                  : notice.kind === "wildcard"
                    ? text.wildcard(notice.ruleId ?? "", notice.path ?? "", notice.count ?? 0)
                    : text.broad(notice.ruleId ?? "", notice.path ?? "", notice.count ?? 0)}
        </Notice>
      ))}
      {baselineNotices(result.baseline).map((notice) => (
        <Notice key={`${notice.kind}:${notice.text}`} tone="warning">
          {notice.kind === "uncertain"
            ? m.scan.baselineNotice.uncertain(notice.count ?? 0)
            : m.scan.baselineNotice.tool}
        </Notice>
      ))}
    </>
  );
}
