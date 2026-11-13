// The Request page: open a link or token, load the key and verify the plan,
// edit a grant (expiry, calls, caps), type the confirmation word, sign.
import { applyEdit, closeRequest, editorChanged, editorDefaults, editorDirty, handleUrl, sign, store, verify } from "../app";
import { field, h } from "../dom";
import { buildRequest, combineExpiry, EditError, expiryParts, fieldsOf, LOCAL, outOfRange, ZONES, type EditorPlan, type Fields } from "../editor";
import { t } from "../i18n";
import { canSign, requestBusy } from "../machines";
import { noteText, show, syncLog, utcAndLocal } from "./common";

export class RequestView {
  readonly root = h("section", { class: "page", "data-testid": "page-request" });
  private heading = h("h2", { "data-testid": "request-heading" });
  private none = h("p", { class: "muted" });
  private pasteInput = h("input", { type: "text", spellcheck: false, autocomplete: "off", "data-testid": "paste-input" });
  private pasteButton = h("button", { type: "button", "data-testid": "paste-open" });
  private pasteRow = h("div", { class: "row paste" });
  private loadButton = h("button", { type: "button", onclick: () => void verify(), "data-testid": "request-load" });
  private closeButton = h("button", { type: "button", class: "link-button", onclick: () => void closeRequest(), "data-testid": "request-close" });
  private editorBox = h("fieldset", { class: "card editor", "data-testid": "editor" });
  private editorTitle = h("legend", {});
  private editorBody = h("div", { class: "editor-body" });
  private editorFor: unknown = null;
  private summaryTitle = h("h3", { class: "small-title" });
  private summary = h("pre", { class: "summary", "data-testid": "summary" });
  private summaryBox = h("div", { class: "stack" });
  private wordLabel = h("span", { class: "field-label" });
  private word = h("input", { type: "text", autocomplete: "off", autocapitalize: "characters", spellcheck: false, class: "word", "data-testid": "confirm-word" });
  private signButton = h("button", { type: "button", class: "danger", "data-testid": "sign" });
  private signRow = h("div", { class: "row wrap sign-row" });
  private dirtyNote = h("p", { class: "muted small" });
  private result = h("p", { class: "result", "data-testid": "result" });
  private logTitle = h("h3", { class: "small-title" });
  private logBox = h("pre", { class: "log", "data-testid": "request-log" });

  constructor() {
    this.pasteButton.addEventListener("click", () => this.paste());
    this.pasteInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") this.paste();
    });
    this.signButton.addEventListener("click", () => void this.sign());
    this.word.addEventListener("input", () => this.updateSign());
    this.word.addEventListener("keydown", (event) => {
      if (event.key === "Enter") void this.sign();
    });
    this.pasteRow.append(this.pasteInput, this.pasteButton);
    this.editorBox.append(this.editorTitle, this.editorBody);
    this.summaryBox.append(this.summaryTitle, this.summary);
    this.signRow.append(h("label", { class: "field inline" }, this.wordLabel, this.word), this.signButton);
    this.root.append(
      h("div", { class: "row" }, this.heading, h("span", { class: "spacer" }), this.closeButton),
      this.none,
      this.pasteRow,
      this.loadButton,
      this.editorBox,
      this.summaryBox,
      this.signRow,
      this.dirtyNote,
      this.result,
      this.logTitle,
      this.logBox,
    );
    this.update();
  }

  private paste(): void {
    const value = this.pasteInput.value;
    this.pasteInput.value = "";
    void handleUrl(value);
  }

  private async sign(): Promise<void> {
    const typed = this.word.value;
    if (await sign(typed)) this.word.value = "";
  }

  private updateSign(): void {
    const state = store.request;
    const dirty = editorDirty();
    this.signButton.disabled = !canSign(state, dirty) || this.word.value.trim().length === 0;
    show(this.dirtyNote, state.phase === "verified" && dirty);
  }

  update(): void {
    const state = store.request;
    const link = "link" in state ? state.link : null;
    const busy = requestBusy(state);
    this.heading.textContent = !link
      ? t("tabs.request")
      : link.action === "revoke"
        ? t("request.headingRevoke")
        : t("request.headingSign");
    this.none.textContent = t("request.none");
    this.pasteInput.placeholder = t("request.paste");
    this.pasteButton.textContent = t("request.open");
    this.loadButton.textContent = t("request.load");
    this.closeButton.textContent = t("request.close");
    this.summaryTitle.textContent = t("request.summary");
    this.signButton.textContent = t("sign.button");
    this.dirtyNote.textContent = t("editor.dirty");
    this.logTitle.textContent = t("status.progress");
    show(this.none, state.phase === "empty");
    show(this.pasteRow, state.phase === "empty" || state.phase === "ready" || state.phase === "done");
    show(this.closeButton, !!link && !busy);
    show(this.loadButton, state.phase === "ready" || state.phase === "verifying" || state.phase === "done");
    this.loadButton.disabled = state.phase === "verifying" || store.keyBusy;

    const session = "session" in state ? state.session : null;
    show(this.summaryBox, !!session);
    this.summary.textContent = session?.summary ?? "";
    show(this.signRow, !!session);
    if (session) this.wordLabel.textContent = t("sign.type", { word: session.confirmWord });
    this.word.disabled = state.phase !== "verified";

    const plan = session?.editor ?? null;
    show(this.editorBox, !!plan);
    this.editorTitle.textContent = t("editor.title");
    if (plan && this.editorFor !== plan) {
      this.editorFor = plan;
      this.buildEditor(plan);
    } else if (!plan) {
      this.editorFor = null;
      this.editorBody.replaceChildren();
    }
    this.editorBody.querySelectorAll<HTMLInputElement | HTMLButtonElement | HTMLSelectElement>("input, button, select").forEach((element) => {
      element.disabled = state.phase !== "verified";
    });
    this.updateEditorNotes();
    this.updateSign();

    show(this.result, state.phase === "done");
    if (state.phase === "done") {
      this.result.textContent = `${t("result.done", { tx: state.result.txHash, block: state.result.block })} ${t(state.result.reported ? "result.reported" : "result.onChain")}`;
    }
    syncLog(this.logBox, store.logs.request);
    show(this.logTitle, store.logs.request.length > 0);
    show(this.logBox, store.logs.request.length > 0);
  }

  // ---------------------------------------------------------------- editor

  private dateInput = h("input", { type: "date", "data-testid": "edit-date" });
  private timeInput = h("input", { type: "time", step: 1, "data-testid": "edit-time" });
  private zoneInput = h("input", { type: "text", list: "helix-zones", "data-testid": "edit-zone", class: "zone" });
  private callsInput = h("input", { type: "text", inputmode: "numeric", class: "short", "data-testid": "edit-calls" });
  private ruleInputs: { perCall: HTMLInputElement; perDay: HTMLInputElement }[] = [];
  private echo = h("p", { class: "muted small", "data-testid": "edit-echo" });
  private editError = h("p", { class: "error-text", "data-testid": "edit-error" });

  private fields(): Fields {
    return {
      date: this.dateInput.value,
      time: this.timeInput.value,
      zone: this.zoneInput.value || LOCAL,
      calls: this.callsInput.value,
      rules: this.ruleInputs.map((row) => ({ maxPerCall: row.perCall.value, maxPerDay: row.perDay.value })),
    };
  }

  private onEdit = () => {
    editorChanged(this.fields());
    this.updateEditorNotes();
    this.updateSign();
  };

  private buildEditor(plan: EditorPlan): void {
    const fields = store.editor.fields ?? fieldsOf(plan, store.editor.zone);
    this.dateInput.value = fields?.date ?? "";
    this.timeInput.value = fields?.time ?? "";
    this.zoneInput.value = store.editor.zone;
    this.callsInput.value = fields?.calls ?? String(plan.remainingCalls);
    const zones = h("datalist", { id: "helix-zones" }, ZONES.map((zone) => h("option", { value: zone })));
    for (const input of [this.dateInput, this.timeInput, this.zoneInput, this.callsInput]) {
      input.oninput = this.onEdit;
      input.onkeydown = (event) => {
        if ((event as KeyboardEvent).key === "Enter") void applyEdit();
      };
    }
    this.zoneInput.onchange = () => {
      // Changing only the zone re-shows the same moment in that zone.
      const previous = store.editor.zone;
      const zone = this.zoneInput.value || LOCAL;
      try {
        const moment = combineExpiry(this.dateInput.value, this.timeInput.value, previous);
        store.editor.zone = zone;
        const { date, time } = expiryParts(moment, zone);
        this.dateInput.value = date;
        this.timeInput.value = time;
      } catch {
        store.editor.zone = zone;
      }
      this.onEdit();
    };
    const rows = plan.rules.map((rule, position) => {
      const value = fields?.rules[position];
      const perCall = h("input", { type: "text", inputmode: "decimal", value: value?.maxPerCall ?? rule.maxPerCall, "data-testid": `edit-call-${position}` });
      const perDay = h("input", { type: "text", inputmode: "decimal", value: value?.maxPerDay ?? rule.maxPerDay, "data-testid": `edit-day-${position}` });
      for (const input of [perCall, perDay]) {
        input.oninput = this.onEdit;
        input.onkeydown = (event) => {
          if ((event as KeyboardEvent).key === "Enter") void applyEdit();
        };
      }
      return { rule, perCall, perDay };
    });
    this.ruleInputs = rows.map(({ perCall, perDay }) => ({ perCall, perDay }));
    const range = (bound?: { min: number | string; max: number | string }) =>
      bound ? h("span", { class: "muted small" }, t("editor.range", { min: bound.min, max: bound.max })) : null;
    const table = h(
      "div",
      { class: "rules" },
      h("div", { class: "rules-head muted small" }, h("span", {}, t("editor.rule")), h("span", {}, t("editor.perCall")), h("span", {}, t("editor.perDay"))),
      rows.map(({ rule, perCall, perDay }, position) =>
        h(
          "div",
          { class: "rules-row" },
          h("span", { class: "rule-name" }, `${position + 1}. ${rule.method} (${rule.unit})`),
          h("span", { class: "cap" }, perCall, range(rule.bounds?.maxPerCall)),
          h("span", { class: "cap" }, perDay, range(rule.bounds?.maxPerDay)),
        ),
      ),
    );
    this.editorBody.replaceChildren(
      h(
        "div",
        { class: "row wrap editor-top" },
        field(t("editor.expires"), this.dateInput),
        field(t("editor.time"), this.timeInput),
        field(t("editor.zone"), this.zoneInput, zones),
        field(t("editor.calls"), this.callsInput),
        h("span", { class: "spacer" }),
        h("button", { type: "button", class: "secondary", onclick: () => void editorDefaults(), "data-testid": "edit-defaults" }, t("editor.defaults")),
        h("button", { type: "button", onclick: () => void applyEdit(), "data-testid": "edit-apply" }, t("editor.apply")),
      ),
      this.echo,
      table,
      this.editError,
    );
    this.onEdit();
  }

  private updateEditorNotes(): void {
    const state = store.request;
    const plan = "session" in state ? state.session.editor : null;
    if (!plan) return;
    const fields = this.fields();
    const lines: string[] = [];
    try {
      const moment = combineExpiry(fields.date, fields.time, fields.zone);
      const { utc, local } = utcAndLocal(moment);
      lines.push(t("editor.echo", { utc, local }));
    } catch (error) {
      if (error instanceof EditError) lines.push(t(error.key, error.params));
    }
    const until = plan.bounds?.validUntil;
    if (until) {
      lines.push(t("editor.allowed", { min: utcAndLocal(Number(until.min)).utc + " UTC", max: utcAndLocal(Number(until.max)).utc + " UTC" }));
    }
    const calls = plan.bounds?.remainingCalls;
    if (calls) lines.push(t("editor.callsAllowed", { min: calls.min, max: calls.max }));
    this.echo.textContent = lines.join("\n");
    let problem = store.editor.error ? noteText(store.editor.error) : "";
    if (!problem) {
      try {
        const request = buildRequest(plan, fields);
        problem = outOfRange(plan, request).map((item) => t(item.key, item.params)).join(" ");
      } catch (error) {
        if (error instanceof EditError) problem = t(error.key, error.params);
      }
    }
    this.editError.textContent = problem;
    if (state.phase === "applying") this.editError.textContent = t("editor.applying");
  }
}
