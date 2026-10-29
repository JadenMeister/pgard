import { useState } from "react";
import { FIX_DISCLAIMER, parseLineReplacementDiff, type Finding } from "@pgard/findings";
import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";

/** Text of this block only, so the shared message catalogs stay untouched. */
const TEXT = {
  en: {
    heading: "Suggested fix (to review)",
    copy: "Copy diff",
    copied: "Copied",
    copyFailed: "Copy failed: select the diff and copy it by hand",
    guidance:
      "No code change is suggested for this finding: the code around it needs a person to decide. Follow the recommendation above.",
  },
  ko: {
    heading: "제안된 수정 (검토용)",
    copy: "diff 복사",
    copied: "복사됨",
    copyFailed: "복사하지 못했습니다. diff를 직접 선택해 복사하세요",
    guidance:
      "이 발견 항목에는 코드 변경을 제안하지 않습니다. 주변 코드는 사람이 판단해야 합니다. 위의 권장 조치를 따르세요.",
  },
} as const;

type CopyState = "idle" | "copied" | "failed";

/**
 * The suggested fix of a finding, read-only: the label says it is a suggestion that PGARD has not
 * applied or verified, the diff is shown as plain text (never as markup) and can be copied. The
 * diff is shown only when it reads back as one of PGARD's own single-line diffs; anything else in
 * a stored or edited result is ignored. Nothing here writes to the scanned files.
 */
export function FixSuggestion({ finding }: { finding: Finding }) {
  const { language } = useI18n();
  const [copy, setCopy] = useState<CopyState>("idle");
  const text = TEXT[language];
  const fix = finding.fix;
  if (fix === undefined) return null;
  const diff =
    fix.kind === "diff" && fix.diff !== undefined && parseLineReplacementDiff(fix.diff) !== null
      ? fix.diff
      : null;
  const onCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(diff ?? "");
      setCopy("copied");
    } catch {
      setCopy("failed");
    }
  };
  return (
    <div className="fix-suggestion">
      <h4>{text.heading}</h4>
      <p className="suppression-reason">{FIX_DISCLAIMER[language]}</p>
      {diff === null ? (
        <p>{text.guidance}</p>
      ) : (
        <>
          <pre aria-label={text.heading}>{diff}</pre>
          <Button size="sm" onClick={() => void onCopy()}>
            {copy === "copied" ? text.copied : text.copy}
          </Button>
          {copy === "failed" && <p role="status">{text.copyFailed}</p>}
        </>
      )}
    </div>
  );
}
