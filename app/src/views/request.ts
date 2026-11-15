// The Request page: open a link or token, load the key and verify the plan,
// edit a grant (expiry, calls, caps), type the confirmation word, sign.
import { applyEdit, closeRequest, editorChanged, editorDefaults, editorDirty, handleUrl, sign, store, verify } from "../app";
import { field, h } from "../dom";
import { buildRequest, combineExpiry, EditError, expiryParts, fieldsOf, isLocalZone, LOCAL, outOfRange, ZONES, type EditorPlan, type Fields } from "../editor";
import { formatDate, formatNumber, getLanguage, t, tParts, unitName, type Parts } from "../i18n";
import { canSign, requestBusy } from "../machines";
import { noteParts, partsNodes, renderSummary, show, syncLog } from "./common";

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
  private summary = h("div", { class: "summary", "data-testid": "summary" });
  private summaryFor: unknown = null;
  private summaryBox = h("div", { class: "stack" });
  private wordLabel = h("span", { class: "field-label" });
  private word = h("input", { type: "text", autocomplete: "off", autocapitalize: "characters", spellcheck: false, class: "word", "data-testid": "confirm-word" });
  private signButton = h("button", { type: "button", class: "danger", "data-testid": "sign" });
  private signRow = h("div", { class: "row wrap sign-row" });
  private dirtyNote = h("p", { class: "muted small" });
  private result = h("p", { class: "result", "data-testid": "result" });
  private logTitle = h("h3", { class: "small-title" });
  private logBox = h("div", { class: "log", "data-testid": "request-log" });

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
    // Rendered from the verified data, again after a language change.
    const summaryKey = session ? [session.summaryData, getLanguage()] : null;
    if (!session) {
      this.summaryFor = null;
      renderSummary(this.summary, null);
    } else if (!Array.isArray(this.summaryFor) || this.summaryFor[0] !== summaryKey![0] || this.summaryFor[1] !== summaryKey![1]) {
      this.summaryFor = summaryKey;
      renderSummary(this.summary, session.summaryData);
    }
    show(this.signRow, !!session);
    if (session) this.wordLabel.textContent = t("sign.type", { word: session.confirmWord });
    this.word.disabled = state.phase !== "verified";

    const plan = session?.editor ?? null;
    show(this.editorBox, !!plan);
    this.editorTitle.textContent = t("editor.title");
    if (plan && (this.editorFor !== plan || this.editorLanguage !== getLanguage())) {
      // A new plan, or another language: build the fields again (typed values stay).
      this.editorFor = plan;
      this.editorLanguage = getLanguage();
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
      this.result.replaceChildren(
        h("span", {}, t("result.done", { tx: state.result.txHash, block: state.result.block })),
        " ",
        h("span", {}, t(state.result.reported ? "result.reported" : "result.onChain")),
      );
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
  private editorLanguage = "";
  private ruleInputs: { perCall: HTMLInputElement; perDay: HTMLInputElement }[] = [];
  private echo = h("div", { class: "muted small", "data-testid": "edit-echo" });
  private editError = h("div", { class: "error-text", "data-testid": "edit-error" });

  private fields(): Fields {
    return {
      date: this.dateInput.value,
      time: this.timeInput.value,
      zone: isLocalZone(this.zoneInput.value) ? LOCAL : this.zoneInput.value,
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
    this.zoneInput.value = isLocalZone(store.editor.zone) ? t("editor.zoneLocal") : store.editor.zone;
    this.callsInput.value = fields?.calls ?? String(plan.remainingCalls);
    const zones = h("datalist", { id: "helix-zones" }, ZONES.map((zone) => h("option", { value: zone === LOCAL ? t("editor.zoneLocal") : zone })));
    for (const input of [this.dateInput, this.timeInput, this.zoneInput, this.callsInput]) {
      input.oninput = this.onEdit;
      input.onkeydown = (event) => {
        if ((event as KeyboardEvent).key === "Enter") void applyEdit();
      };
    }
    this.zoneInput.onchange = () => {
      // Changing only the zone re-shows the same moment in that zone.
      const previous = store.editor.zone;
      const zone = isLocalZone(this.zoneInput.value) ? LOCAL : this.zoneInput.value;
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
          h("span", { class: "rule-name" }, t("editor.ruleName", { index: position + 1, method: rule.method, unit: unitName(rule.unit) })),
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
        field(t("editor.calls"), this.callsInput, h("span", { class: "field-help", "data-testid": "edit-calls-help" }, t("editor.callsHelp"))),
        h("span", { class: "spacer" }),
        h("button", { type: "button", class: "secondary", onclick: () => void editorDefaults(), "data-testid": "edit-defaults" }, t("editor.defaults")),
        h("button", { type: "button", onclick: () => void applyEdit(), "data-testid": "edit-apply" }, t("editor.apply")),
      ),
      this.echo,
      table,
      this.editError,
    );
    // Rebuilt for a new plan or language: the fields stay, so does a website refusal shown for them.
    store.editor.fields = this.fields();
    this.updateEditorNotes();
    this.updateSign();
  }

  private updateEditorNotes(): void {
    const state = store.request;
    const plan = "session" in state ? state.session.editor : null;
    if (!plan) return;
    const fields = this.fields();
    const lines: string[] = [];
    try {
      const moment = combineExpiry(fields.date, fields.time, fields.zone);
      lines.push(t("editor.echo", { utc: formatDate(moment, "UTC"), local: formatDate(moment, "local") }));
    } catch (error) {
      if (error instanceof EditError) lines.push(t(error.key, error.params));
    }
    const until = plan.bounds?.validUntil;
    if (until) {
      lines.push(t("editor.allowed", { min: formatDate(Number(until.min), "UTC") + " UTC", max: formatDate(Number(until.max), "UTC") + " UTC" }));
    }
    const calls = plan.bounds?.remainingCalls;
    if (calls) lines.push(t("editor.callsAllowed", { min: formatNumber(Number(calls.min)), max: formatNumber(Number(calls.max)) }));
    this.echo.replaceChildren(...lines.map((line) => h("div", {}, line)));
    let problems: Parts[] = store.editor.error ? [noteParts(store.editor.error)] : [];
    if (!problems.length) {
      try {
        const request = buildRequest(plan, fields);
        problems = outOfRange(plan, request).map((item) => tParts(item.key, item.params));
      } catch (error) {
        if (error instanceof EditError) problems = [tParts(error.key, error.params)];
      }
    }
    if (state.phase === "applying") problems = [{ text: t("editor.applying"), raw: [] }];
    this.editError.replaceChildren(...problems.map((parts) => h("div", {}, partsNodes(parts))));
  }
}
