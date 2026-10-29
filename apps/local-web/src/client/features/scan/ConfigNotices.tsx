import { projectConfigNotices, type Coverage } from "@pgard/findings";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";

/**
 * What pgard.config.json did to this scan (excluded files, reclassified findings, an invalid
 * file), above the coverage table. The framing is translated; the detail is the coverage note.
 */
export function ConfigNotices({ coverage }: { coverage: readonly Coverage[] }) {
  const { m } = useI18n();
  return (
    <>
      {projectConfigNotices(coverage)
        .filter((notice) => notice.tone === "warning")
        .map((notice) => (
          <Notice key={`${notice.kind}:${notice.text}`} tone="warning">
            {notice.kind === "demoted"
              ? m.scan.configNotice.demoted(notice.count ?? 0)
              : m.scan.configNotice[notice.kind](notice.text)}
          </Notice>
        ))}
    </>
  );
}
