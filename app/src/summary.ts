// The verified summary in the selected language, rendered from the data the
// core decoded from the calldata (helix_signer_core::Summary): the same facts,
// line for line, as the command line's English text (Summary::text).
import type { RuleSummary, Summary } from "./api";
import { formatNumber, formatWhen, t, tParts, unitName, type Parts } from "./i18n";

export interface SummaryLine {
  parts: Parts;
  /** 0: a heading line, 1: a rule, 2: a rule's detail. */
  indent: number;
  warning?: boolean;
}

/** An address with its pinned contract name: "PowerLedger (0x…)". */
export function named(address: string, name: string): string {
  return name ? `${name} (${address})` : address;
}

/** The website's list of customized fields, in words. */
function fieldName(field: string): string {
  if (field === "validUntil") return t("summary.field.validUntil");
  if (field === "remainingCalls") return t("summary.field.remainingCalls");
  const rule = /^rules\[(\d+)\]\.(maxPerCall|maxPerDay)$/.exec(field);
  if (rule) return t(`summary.field.${rule[2]}`, { rule: Number(rule[1]) + 1 });
  return field;
}

function ruleLines(rule: RuleSummary): SummaryLine[] {
  const lines: SummaryLine[] = [
    { indent: 1, parts: tParts("summary.rule", { index: rule.index, method: rule.method, target: named(rule.target, rule.targetName) }) },
  ];
  const detail = (key: string, params: Record<string, string | number>) => lines.push({ indent: 2, parts: tParts(key, params) });
  if (rule.spender) detail("summary.spender", { spender: named(rule.spender, rule.spenderName) });
  if (rule.swap) {
    detail("summary.swap", { from: named(rule.swap.tokenIn, rule.swap.tokenInName), to: named(rule.swap.tokenOut, rule.swap.tokenOutName) });
    detail("summary.priceFloor", {
      floor: rule.swap.priceFloor,
      out: rule.swap.tokenOutName || t("summary.output"),
      in: rule.swap.tokenInName || t("summary.input"),
    });
  }
  detail("summary.limit", { perCall: rule.maxPerCall, perDay: rule.maxPerDay, unit: unitName(rule.unit) });
  if (rule.activationDai !== null) detail("summary.activation", { amount: rule.activationDai });
  if (rule.deadlineSeconds !== null) detail("summary.deadline", { seconds: formatNumber(rule.deadlineSeconds) });
  return lines;
}

/** The summary's lines in the current language. */
export function summaryLines(summary: Summary): SummaryLine[] {
  const lines: SummaryLine[] = [];
  const line = (key: string, params: Record<string, string | number> = {}, warning = false) =>
    lines.push({ indent: 0, parts: tParts(key, params), warning });
  line("summary.version", { version: summary.signerVersion });
  if (summary.website) {
    line("summary.website", { api: summary.website });
    if (!summary.officialWebsite) line("summary.notOfficial", {}, true);
  }
  line("summary.chain", { chainId: summary.chainId, rpc: summary.rpcUrl });
  if (summary.development) line("summary.development", {}, true);
  line("summary.owner", { owner: summary.owner });
  const grant = summary.grant;
  const revoke = summary.revoke;
  if (grant) {
    line("summary.transaction", { transaction: t(grant.delegates ? "summary.tx.delegateInstall" : "summary.tx.selfCallInstall") });
    line(grant.codeHashVerified ? "summary.delegateVerified" : "summary.delegate", { delegate: grant.delegate });
    line("summary.sessionKey", { key: grant.sessionKey });
    if (grant.botScript) line("summary.bot", { script: grant.botScript, id: grant.botId });
    else line("summary.botId", { id: grant.botId });
    line("summary.grantId", { grant: grant.grantId });
    line("summary.validFrom", { when: formatWhen(grant.validAfter) });
    line("summary.expires", { when: formatWhen(grant.validUntil) });
    line("summary.calls", { calls: formatNumber(grant.remainingCalls) });
    line("summary.rules");
    grant.rules.forEach((rule) => lines.push(...ruleLines(rule)));
    if (grant.customized.length) line("summary.customized", { fields: grant.customized.map(fieldName).join(t("common.listSeparator")) });
    line("summary.value");
    line("summary.gas", { balance: summary.balance });
    line("summary.grantNote");
    line("summary.revokeAnyTime");
  }
  if (revoke) {
    line("summary.transaction", {
      transaction: t(revoke.redelegates ? "summary.tx.redelegateRevoke" : "summary.tx.selfCallRevoke", { method: revoke.method }),
    });
    line("summary.revokeGrant", { grant: revoke.grantId, kind: t(`summary.kind.${revoke.grantKind}`) });
    if (revoke.redelegates) line("summary.redelegation", { delegate: named(revoke.delegate, revoke.delegateName) });
    else line("summary.delegation", { target: revoke.delegation });
    line("summary.value");
    line("summary.gas", { balance: summary.balance });
    line("summary.revokeNote");
  }
  return lines;
}
