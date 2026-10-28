import {
  baselineNotices,
  suppressionNotices,
  type ScanResult,
  type SuppressionNotice,
} from "@pgard/findings";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";

type Text = ReturnType<typeof useI18n>["m"]["scan"]["suppressionNotice"];

function noticeText(notice: SuppressionNotice, text: Text): string {
  const rule = notice.ruleId ?? "";
  const path = notice.path ?? "";
  const count = notice.count ?? 0;
  switch (notice.kind) {
    case "severe":
      return text.severe(count, notice.high ?? 0, notice.critical ?? 0);
    case "everything":
      return text.everything(count);
    case "incomplete":
      return text.incomplete;
    case "expired":
      return text.expired(rule, path, notice.expires ?? "?");
    case "far":
      return text.far(rule, path, notice.expires ?? "?");
    case "wildcard":
      return text.wildcard(rule, path, count);
    case "total":
      return text.total(count);
    case "broad":
      return text.broad(rule, path, count);
    case "noexpiry":
      return notice.text;
  }
}

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
      {suppressionNotices(result)
        .filter((notice) => notice.tone === "warning")
        .map((notice) => (
          <Notice key={`${notice.kind}:${notice.text}`} tone="warning">
            {noticeText(notice, text)}
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
