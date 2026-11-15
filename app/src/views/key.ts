// The key box: keystore file / private key / mnemonic + account index. Secret
// fields are password inputs that are read once at use and cleared at once.
import { api, errorMsg, plainMsg, type CommandError } from "../api";
import { changed, forgetKey, store, useSecrets, type KeyKind } from "../app";
import { confirmDialog, field, h } from "../dom";
import { pickKeystore, saveKeystore } from "../files";
import { onLanguage, t } from "../i18n";
import { show } from "./common";

export class KeyView {
  readonly root = h("section", { class: "card key", "data-testid": "key-panel" });
  private form = h("div", { class: "key-form" });
  private loaded = h("div", { class: "row key-loaded", "data-testid": "key-loaded" });
  private loadedText = h("span", { class: "mono", "data-testid": "key-address" });
  private sources = new Map<KeyKind, HTMLInputElement>();
  private sourceLabels = new Map<KeyKind, HTMLSpanElement>();
  private fileButton = h("button", { type: "button", class: "secondary", "data-testid": "key-file" });
  private fileName = h("span", { class: "muted file-name", "data-testid": "key-file-name" });
  private password = h("input", { type: "password", autocomplete: "off", "data-testid": "key-password" });
  private privateKey = h("input", { type: "password", autocomplete: "off", spellcheck: false, "data-testid": "key-private" });
  private mnemonic = h("textarea", { rows: 2, autocomplete: "off", spellcheck: false, class: "secret", "data-testid": "key-mnemonic" });
  private index = h("input", { type: "text", inputmode: "numeric", value: "0", class: "short", "data-testid": "key-index" });
  private keystoreRow: HTMLElement;
  private privateRow: HTMLElement;
  private mnemonicRow: HTMLElement;
  private warning = h("p", { class: "warning" });
  private hint = h("p", { class: "muted small" });
  private title = h("h2", {});
  private sourceTitle = h("legend", {});
  private passwordLabel: HTMLLabelElement;
  private privateLabel: HTMLLabelElement;
  private mnemonicLabel: HTMLLabelElement;
  private indexLabel: HTMLLabelElement;
  private forgetButton = h("button", { type: "button", class: "secondary", onclick: () => void forgetKey(), "data-testid": "key-forget" });
  private saveButton = h("button", { type: "button", class: "secondary", onclick: () => void this.save(), "data-testid": "key-save" });

  constructor() {
    useSecrets({
      read: () => ({ password: this.password.value, privateKey: this.privateKey.value, mnemonic: this.mnemonic.value }),
      clear: () => {
        this.password.value = "";
        this.privateKey.value = "";
        this.mnemonic.value = "";
      },
    });
    const radios = h("div", { class: "row wrap", role: "radiogroup" });
    for (const kind of ["keystore", "privateKey", "mnemonic"] as const) {
      const input = h("input", {
        type: "radio",
        name: "key-source",
        value: kind,
        checked: kind === store.keyForm.source,
        onchange: () => {
          store.keyForm.source = kind;
          this.update();
        },
        "data-testid": `key-source-${kind}`,
      });
      const label = h("span", {});
      this.sources.set(kind, input);
      this.sourceLabels.set(kind, label);
      radios.appendChild(h("label", { class: "radio" }, input, label));
    }
    this.fileButton.addEventListener("click", () => void this.pick());
    this.index.addEventListener("input", () => (store.keyForm.index = this.index.value));
    this.passwordLabel = field("", this.password);
    this.privateLabel = field("", this.privateKey);
    this.mnemonicLabel = field("", this.mnemonic);
    this.indexLabel = field("", this.index);
    this.keystoreRow = h("div", { class: "stack" }, h("div", { class: "row wrap" }, this.fileButton, this.fileName), this.passwordLabel);
    this.privateRow = h("div", { class: "stack" }, this.privateLabel);
    this.mnemonicRow = h("div", { class: "stack" }, this.mnemonicLabel, this.indexLabel, this.warning);
    this.form.append(h("fieldset", { class: "plain" }, this.sourceTitle, radios), this.keystoreRow, this.privateRow, this.mnemonicRow, this.hint);
    this.loaded.append(this.loadedText, h("span", { class: "spacer" }), this.saveButton, this.forgetButton);
    this.root.append(this.title, this.form, this.loaded);
    this.update();
  }

  private async pick(): Promise<void> {
    try {
      const picked = await pickKeystore(store.info?.mobile ?? false);
      if (!picked) return;
      store.keyForm.path = picked.path ?? "";
      store.keyForm.json = picked.json ?? "";
      store.keyForm.fileName = picked.name;
      this.update();
    } catch (error) {
      // The dialog plugin's own text (English) is the detail.
      store.status = { key: "key.pickFailed", params: { message: plainMsg("io", String((error as Error)?.message ?? error)) }, tone: "error" };
      changed();
    }
  }

  /** Save the loaded key as an encrypted keystore where the user chooses. */
  private async save(): Promise<void> {
    const key = store.key;
    if (!key) return;
    const first = h("input", { type: "password", autocomplete: "new-password", "data-testid": "save-password" });
    const second = h("input", { type: "password", autocomplete: "new-password", "data-testid": "save-password2" });
    const problem = h("p", { class: "error-text" });
    const dialog = h("dialog", { class: "modal", "data-testid": "save-dialog" });
    // Texts are rendered again when the language changes while the dialog is open.
    let problemKey: "key.passwordShort" | "key.passwordMismatch" | null = null;
    const heading = h("h3", {});
    const firstField = field("", first);
    const secondField = field("", second);
    const cancel = h("button", { type: "button", class: "secondary", "data-testid": "save-cancel" });
    const save = h("button", { type: "button", "data-testid": "save-confirm" });
    const render = () => {
      heading.textContent = t("key.save");
      (firstField.firstChild as HTMLElement).textContent = t("key.newPassword");
      (secondField.firstChild as HTMLElement).textContent = t("key.repeatPassword");
      problem.textContent = problemKey ? t(problemKey) : "";
      cancel.textContent = t("common.cancel");
      save.textContent = t("common.save");
    };
    const stop = onLanguage(render);
    const result = await new Promise<string | null>((resolve) => {
      const done = (value: string | null) => {
        stop();
        dialog.close?.();
        dialog.remove();
        resolve(value);
      };
      cancel.onclick = () => done(null);
      save.onclick = () => {
        problemKey = first.value.length < 8 ? "key.passwordShort" : first.value !== second.value ? "key.passwordMismatch" : null;
        render();
        if (!problemKey) done(first.value);
      };
      render();
      dialog.append(heading, firstField, secondField, problem, h("div", { class: "row end" }, cancel, save));
      document.body.appendChild(dialog);
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    });
    first.value = "";
    second.value = "";
    if (result === null) return;
    try {
      const json = await api.exportKeystore(result);
      const path = await saveKeystore(json, key.address);
      if (path) store.status = { key: "key.saved", params: { path }, tone: "ok" };
    } catch (error) {
      const failure = error as CommandError;
      store.status = { key: "status.error", params: { message: errorMsg(failure?.message ? failure : { kind: "error", message: String(error) }) }, tone: "error" };
    }
    changed();
  }

  /** Ask before wiping (used by the This computer page). */
  static async confirmForget(): Promise<void> {
    if (await confirmDialog(() => t("key.forgetConfirm"), () => t("common.yes"), () => t("common.no"))) await forgetKey();
  }

  update(): void {
    const source = store.keyForm.source;
    this.title.textContent = t("key.title");
    this.sourceTitle.textContent = t("key.source");
    for (const [kind, label] of this.sourceLabels) label.textContent = t(`key.source.${kind}`);
    for (const [kind, input] of this.sources) input.checked = kind === source;
    this.fileButton.textContent = t("key.chooseFile");
    this.fileName.textContent = store.keyForm.fileName || t("key.noFile");
    this.fileName.toggleAttribute("data-raw", !!store.keyForm.fileName);
    (this.passwordLabel.firstChild as HTMLElement).textContent = t("key.password");
    (this.privateLabel.firstChild as HTMLElement).textContent = t("key.privateKey");
    (this.mnemonicLabel.firstChild as HTMLElement).textContent = t("key.mnemonic");
    (this.indexLabel.firstChild as HTMLElement).textContent = t("key.index");
    this.warning.textContent = t("key.mnemonicWarning");
    this.hint.textContent = t("key.notStored");
    this.forgetButton.textContent = t("key.forget");
    this.saveButton.textContent = t("key.save");
    show(this.keystoreRow, source === "keystore");
    show(this.privateRow, source === "privateKey");
    show(this.mnemonicRow, source === "mnemonic");
    const key = store.key;
    show(this.form, !key);
    show(this.loaded, !!key);
    // A keystore that was just read from a file needs no second copy.
    show(this.saveButton, !!key && key.source !== "keystore");
    this.loadedText.textContent = key ? t("key.loaded", { address: key.address }) : "";
    for (const input of [this.password, this.privateKey, this.mnemonic, this.index, this.fileButton]) {
      input.disabled = store.keyBusy;
    }
  }
}
