import type { IncrementalFullReason, IncrementalInfo, RuleLocale } from "@pgard/findings";

/**
 * The words that say how a scan built on an earlier one (JSON v1.2 `incremental`), shared by the
 * report and the terminal so both say the same thing.
 */
export interface IncrementalText {
  /** Label of the line when the scan reused data from an earlier one. */
  label: string;
  /** Label of the line when the scan was a full one. */
  fullScanLabel: string;
  /** "re-scanned 3 files, reused 1997 (based on scan 1a2b3c4d)" */
  value: (info: IncrementalInfo) => string;
  /** Why a scan, or one of its areas, was a full scan. */
  reason: Record<IncrementalFullReason, string>;
}

const shortId = (info: IncrementalInfo): string | null =>
  info.basedOn === null ? null : info.basedOn.scanId.slice(0, 8);

const EN_REASON: Record<IncrementalFullReason, string> = {
  requested_full: "a full scan was requested (--full)",
  no_previous_scan: "no earlier stored scan of this repository",
  store_unavailable: "stored results are turned off or could not be read",
  previous_unreadable: "the stored scan is corrupt, expired or from an incompatible version",
  no_saved_state: "the stored scan has no reusable data",
  scopes_changed: "the stored scan covered other scopes",
  tool_changed: "PGARD, its rules or its grammars changed since the stored scan",
  config_changed: "pgard.config.json changed since the stored scan",
  previous_incomplete: "an area of the stored scan was partial or not tested",
  head_not_ancestor:
    "the stored commit is not in this branch's history (rebase, force-push or another clone)",
  git_failed: "Git could not list the changes since the stored scan",
  rules_unclassified: "a rule is not classified for incremental scans",
  history_changed: "the new commits change what the earlier history findings mean",
};

const KO_REASON: Record<IncrementalFullReason, string> = {
  requested_full: "전체 검사를 요청함 (--full)",
  no_previous_scan: "이 저장소에 저장된 이전 검사가 없음",
  store_unavailable: "검사 결과 저장이 꺼져 있거나 읽을 수 없음",
  previous_unreadable: "저장된 검사가 손상되었거나 만료되었거나 호환되지 않는 버전임",
  no_saved_state: "저장된 검사에 재사용할 데이터가 없음",
  scopes_changed: "저장된 검사의 범위가 다름",
  tool_changed: "저장된 검사 이후 PGARD, 규칙 또는 문법(grammar)이 바뀜",
  config_changed: "저장된 검사 이후 pgard.config.json이 바뀜",
  previous_incomplete: "저장된 검사의 일부 영역이 부분 완료이거나 검사되지 않음",
  head_not_ancestor: "저장된 커밋이 이 브랜치의 이력에 없음 (리베이스, 강제 푸시 또는 다른 복제본)",
  git_failed: "저장된 검사 이후의 변경을 Git으로 확인하지 못함",
  rules_unclassified: "증분 검사용으로 분류되지 않은 규칙이 있음",
  history_changed: "새 커밋 때문에 이전 이력 발견 항목의 의미가 달라짐",
};

const plural = (count: number, one: string, many: string): string => (count === 1 ? one : many);

export const INCREMENTAL_TEXT: Record<RuleLocale, IncrementalText> = {
  en: {
    label: "Incremental",
    fullScanLabel: "Full scan",
    reason: EN_REASON,
    value: (info) => {
      const parts: string[] = [];
      if (info.code?.mode === "incremental" && info.filesRescanned !== null) {
        parts.push(
          `re-scanned ${info.filesRescanned} ${plural(info.filesRescanned, "file", "files")}, reused ${info.filesReused ?? 0}`,
        );
      }
      if (info.history?.mode === "incremental" && info.commitsScanned !== null) {
        parts.push(
          `${info.commitsScanned} new ${plural(info.commitsScanned, "commit", "commits")} scanned, ${info.commitsReused ?? 0} reused`,
        );
      }
      const id = shortId(info);
      const full = [info.code, info.history].flatMap((area, index) =>
        area?.mode === "full" && area.reason !== null
          ? [`${index === 0 ? "code" : "history"} in full: ${EN_REASON[area.reason]}`]
          : [],
      );
      return `${parts.join("; ")}${id === null ? "" : ` (based on scan ${id})`}${full.length > 0 ? `; ${full.join("; ")}` : ""}`;
    },
  },
  ko: {
    label: "증분 검사",
    fullScanLabel: "전체 검사",
    reason: KO_REASON,
    value: (info) => {
      const parts: string[] = [];
      if (info.code?.mode === "incremental" && info.filesRescanned !== null) {
        parts.push(`파일 ${info.filesRescanned}개 다시 검사, ${info.filesReused ?? 0}개 재사용`);
      }
      if (info.history?.mode === "incremental" && info.commitsScanned !== null) {
        parts.push(`새 커밋 ${info.commitsScanned}개 검사, ${info.commitsReused ?? 0}개 재사용`);
      }
      const id = shortId(info);
      const full = [info.code, info.history].flatMap((area, index) =>
        area?.mode === "full" && area.reason !== null
          ? [`${index === 0 ? "코드" : "이력"} 전체 검사: ${KO_REASON[area.reason]}`]
          : [],
      );
      return `${parts.join("; ")}${id === null ? "" : ` (검사 ${id} 기준)`}${full.length > 0 ? `; ${full.join("; ")}` : ""}`;
    },
  },
};

/** "Incremental: ..." or "Full scan: ...", for the report; null when the result has no field. */
export function incrementalLine(
  info: IncrementalInfo | undefined,
  locale: RuleLocale,
): { label: string; value: string } | null {
  if (info === undefined) return null;
  const text = INCREMENTAL_TEXT[locale];
  if (info.used) return { label: text.label, value: text.value(info) };
  return info.reason === null
    ? null
    : { label: text.fullScanLabel, value: text.reason[info.reason] };
}
