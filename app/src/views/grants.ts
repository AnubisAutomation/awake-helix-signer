// My grants: sign in by signing the login challenge locally, list every grant,
// revoke the selected one or all active ones after typing REVOKE.
import type { GrantRow } from "../api";
import { cancelRevoke, confirmRevoke, loadGrants, prepareRevoke, selectGrant, store } from "../app";
import { h } from "../dom";
import { formatDate, formatNumber, getLanguage, t } from "../i18n";
import { short } from "../links";
import { grantsButtons } from "../machines";
import { show, syncLog } from "./common";

// Statuses the website sends; a newer one renders with a neutral label.
export const STATUS_KEYS = new Set(["active", "not_yet_valid", "inactive", "expired", "revoked", "exhausted", "unavailable", "missing"]);

export function statusText(status: string): string {
  if (STATUS_KEYS.has(status)) return t(`grants.status.${status}`);
  const shown = status.replace(/[^\w -]/g, "").replace(/_/g, " ").trim().slice(0, 40);
  return t("grants.status.unknown", { status: shown || "?" });
}

/** CSS class of a row's status: known statuses only, anything else is neutral. */
export function statusClass(status: string): string {
  return STATUS_KEYS.has(status) ? `status-${status}` : "status-other";
}

/** The linked bot in words: its script name and ID are data, the rest is translated. */
export function botText(row: GrantRow): string {
  const name = row.botScript || t("grants.bot.unnamed");
  switch (row.botState) {
    case "none":
      return t("grants.bot.none");
    case "unknown":
      return t("grants.bot.unknown");
    case "deleted":
      return t("grants.bot.deleted", { name });
    case "running":
      return t("grants.bot.running", { name, id: row.botId || "?" });
    case "stopped":
      return t("grants.bot.stopped", { name, id: row.botId || "?" });
    default:
      // An older backend sends only the English text.
      return row.bot;
  }
}

/** Explanations for the statuses shown (dormant, foreign delegation, read failure, never installed). */
export function statusNotes(rows: readonly GrantRow[]): string[] {
  const notes: string[] = [];
  if (rows.some((row) => row.status === "inactive" && row.notRevocableReason !== "otherDelegation")) notes.push(t("grants.note.inactive"));
  if (rows.some((row) => row.notRevocableReason === "otherDelegation")) notes.push(t("grants.note.otherDelegation"));
  if (rows.some((row) => row.status === "unavailable")) notes.push(t("grants.note.unavailable"));
  if (rows.some((row) => row.status === "missing")) notes.push(t("grants.note.missing"));
  return notes;
}

export class GrantsView {
  readonly root = h("section", { class: "page", "data-testid": "page-grants" });
  private help = h("p", { class: "muted" });
  private loadButton = h("button", { type: "button", onclick: () => void loadGrants(), "data-testid": "grants-load" });
  private revokeButton = h("button", { type: "button", class: "secondary", onclick: () => void prepareRevoke(false), "data-testid": "grants-revoke-selected" });
  private revokeAllButton = h("button", { type: "button", class: "secondary", onclick: () => void prepareRevoke(true), "data-testid": "grants-revoke-all" });
  private scan = h("span", { class: "muted small", "data-testid": "grants-scan" });
  private table = h("div", { class: "grants", role: "table", "data-testid": "grants-table" });
  private listed: unknown = null;
  private empty = h("p", { class: "muted", "data-testid": "grants-empty" });
  private notes = h("div", { class: "grants-notes", "data-testid": "grants-notes" });
  private wordLabel = h("span", { class: "field-label" });
  private word = h("input", { type: "text", autocomplete: "off", autocapitalize: "characters", spellcheck: false, class: "word", "data-testid": "grants-word" });
  private confirmButton = h("button", { type: "button", class: "danger", "data-testid": "grants-confirm" });
  private cancelButton = h("button", { type: "button", class: "secondary", onclick: () => void cancelRevoke(), "data-testid": "grants-cancel" });
  private progress = h("progress", { max: 1, value: 0, "data-testid": "grants-progress" });
  private logTitle = h("h3", { class: "small-title" });
  private logBox = h("div", { class: "log", "data-testid": "grants-log" });
  private callsHelp = h("p", { class: "muted small", "data-testid": "grants-calls-help" });

  constructor() {
    this.confirmButton.addEventListener("click", () => void this.confirm());
    this.word.addEventListener("keydown", (event) => {
      if (event.key === "Enter") void this.confirm();
    });
    this.root.append(
      this.help,
      h("div", { class: "row wrap" }, this.loadButton, this.revokeButton, this.revokeAllButton, h("span", { class: "spacer" }), this.scan),
      this.table,
      this.callsHelp,
      this.notes,
      this.empty,
      h("div", { class: "row wrap sign-row" }, h("label", { class: "field inline" }, this.wordLabel, this.word), this.confirmButton, this.cancelButton, h("span", { class: "spacer" }), this.progress),
      this.logTitle,
      this.logBox,
    );
    this.update();
  }

  private async confirm(): Promise<void> {
    const typed = this.word.value;
    this.word.value = "";
    await confirmRevoke(typed);
  }

  private row(row: GrantRow): HTMLElement {
    const until = row.validUntil ? { utc: formatDate(row.validUntil, "UTC"), local: formatDate(row.validUntil, "local") } : null;
    const select = h("input", {
      type: "radio",
      name: "grant",
      value: row.grantId,
      checked: store.grants.selected === row.grantId,
      "aria-label": t("grants.select", { grant: short(row.grantId) }),
      onchange: () => selectGrant(row.grantId),
      "data-testid": `grant-select-${row.grantId}`,
    });
    // Key, dates, counts and IDs are data; status and bot are words.
    const data = new Set(["key", "until", "local", "calls", "grant"]);
    const cell = (column: string, value: string, extra = "") =>
      h("span", { class: `cell ${extra}`, role: "cell", "data-label": t(`grants.col.${column}`), "data-raw": data.has(column) ? "" : undefined }, value);
    return h(
      "label",
      { class: `grant-row ${statusClass(row.status)}`, role: "row", "data-testid": "grant-row", "data-grant": row.grantId, "data-revocable": String(row.revocable) },
      h("span", { class: "cell pick" }, select),
      cell("status", statusText(row.status), "status"),
      cell("key", short(row.key), "mono"),
      cell("bot", botText(row), "bot"),
      cell("until", until?.utc ?? "-", "mono"),
      cell("local", until?.local ?? "-", "mono"),
      cell("calls", row.remainingCalls === null ? "-" : formatNumber(row.remainingCalls)),
      cell("grant", short(row.grantId), "mono"),
    );
  }

  private header(): HTMLElement {
    return h(
      "div",
      { class: "grant-row head", role: "row" },
      h("span", { class: "cell pick" }),
      ["status", "key", "bot", "until", "local", "calls", "grant"].map((column) =>
        h(
          "span",
          { class: "cell", role: "columnheader", title: column === "calls" ? t("editor.callsHelp") : undefined, "data-testid": `grants-col-${column}` },
          t(`grants.col.${column}`),
        ),
      ),
    );
  }

  update(): void {
    const state = store.grants;
    const buttons = grantsButtons(state);
    this.help.textContent = t("grants.help");
    this.loadButton.textContent = store.key && state.listing ? t("grants.refresh") : t("grants.load");
    this.loadButton.disabled = !buttons.load || store.keyBusy;
    this.revokeButton.textContent = t("grants.revokeSelected");
    this.revokeButton.disabled = !buttons.revokeSelected;
    this.revokeAllButton.textContent = t("grants.revokeAll");
    this.revokeAllButton.disabled = !buttons.revokeAll;
    this.confirmButton.textContent = t("sign.button");
    this.confirmButton.disabled = !buttons.confirm;
    this.cancelButton.textContent = t("grants.cancel");
    this.cancelButton.disabled = !buttons.cancel;
    this.wordLabel.textContent = t("grants.type");
    this.word.disabled = !buttons.confirm;
    this.logTitle.textContent = t("status.progress");
    const listing = state.listing;
    const notes: string[] = [];
    if (listing && !listing.scanComplete) notes.push(t("grants.scanning", { percent: listing.scanPercent }));
    if (listing?.truncated) notes.push(t("grants.truncated"));
    this.scan.replaceChildren(...notes.map((note) => h("span", { class: "scan-note" }, note)));
    if (this.listed !== listing || this.table.dataset.language !== getLanguage()) {
      this.listed = listing;
      this.table.dataset.language = getLanguage();
      this.table.replaceChildren(...(listing && listing.rows.length ? [this.header(), ...listing.rows.map((row) => this.row(row))] : []));
      this.notes.replaceChildren(...statusNotes(listing?.rows ?? []).map((text) => h("p", { class: "muted small grants-note" }, text)));
    }
    show(this.notes, this.notes.childElementCount > 0);
    this.table.querySelectorAll<HTMLInputElement>("input[type=radio]").forEach((input) => {
      input.checked = input.value === state.selected;
      input.disabled = state.phase !== "listed";
    });
    show(this.table, !!listing && listing.rows.length > 0);
    // What "Calls allowed" means, under the list.
    this.callsHelp.replaceChildren(h("strong", {}, t("grants.col.calls")), " ", h("span", {}, t("editor.callsHelp")));
    show(this.callsHelp, !!listing && listing.rows.length > 0);
    show(this.empty, !!listing && listing.rows.length === 0);
    this.empty.textContent = t("grants.empty");
    show(this.progress, !!state.progress);
    if (state.progress) {
      this.progress.max = Math.max(1, state.progress.total);
      this.progress.value = state.progress.done;
    }
    syncLog(this.logBox, store.logs.grants);
    show(this.logTitle, store.logs.grants.length > 0);
    show(this.logBox, store.logs.grants.length > 0);
  }
}
