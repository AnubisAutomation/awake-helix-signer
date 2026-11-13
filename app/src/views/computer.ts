// This computer / This device: link registration, the terminal command,
// version, the key in memory and the website's install check.
import { installCli, registerLinks, store } from "../app";
import { h } from "../dom";
import { t } from "../i18n";
import { show } from "./common";
import { KeyView } from "./key";

export class ComputerView {
  readonly root = h("section", { class: "page", "data-testid": "page-computer" });
  private links = h("p", { "data-testid": "setup-links" });
  private command = h("p", { "data-testid": "setup-command" });
  private mobileNote = h("p", { class: "muted" });
  private registerButton = h("button", { type: "button", class: "secondary", onclick: () => void registerLinks(), "data-testid": "setup-register" });
  private cliButton = h("button", { type: "button", class: "secondary", onclick: () => void installCli(), "data-testid": "setup-cli" });
  private version = h("p", { class: "muted", "data-testid": "setup-version" });
  private keyTitle = h("h3", { class: "small-title" });
  private keyText = h("p", { class: "mono" });
  private forgetButton = h("button", { type: "button", class: "secondary", onclick: () => void KeyView.confirmForget(), "data-testid": "setup-forget" });
  private checkTitle = h("h3", { class: "small-title" });
  private checkHelp = h("p", { class: "muted" });

  constructor() {
    this.root.append(
      this.links,
      this.command,
      this.mobileNote,
      h("div", { class: "row wrap" }, this.registerButton, this.cliButton),
      this.version,
      this.keyTitle,
      h("div", { class: "row wrap" }, this.keyText, h("span", { class: "spacer" }), this.forgetButton),
      this.checkTitle,
      this.checkHelp,
    );
    this.update();
  }

  update(): void {
    const setup = store.setup;
    const info = store.info;
    const os = setup?.os ?? info?.os ?? "linux";
    const mobile = setup?.mobile ?? info?.mobile ?? false;
    if (mobile) this.links.textContent = t("computer.linksMobile");
    else if (os === "macos") this.links.textContent = setup?.handler ? t("computer.linksMac", { handler: setup.handler }) : t("computer.linksMacMissing");
    else this.links.textContent = setup?.handler ? t("computer.links", { handler: setup.handler }) : t("computer.linksMissing");
    if (os === "windows") this.command.textContent = t("computer.cliWindows");
    else this.command.textContent = setup?.command ? t("computer.cli", { path: setup.command }) : t("computer.cliMissing");
    show(this.command, !mobile);
    this.mobileNote.textContent = t("computer.mobile");
    show(this.mobileNote, mobile);
    this.registerButton.textContent = t("computer.register");
    show(this.registerButton, !!setup?.canRegister);
    this.cliButton.textContent = t("computer.installCli");
    show(this.cliButton, !!setup?.canInstallCli);
    this.version.textContent = info ? t("computer.version", { version: info.version, os: info.os, arch: info.arch }) : "";
    this.keyTitle.textContent = t("computer.keyTitle");
    this.keyText.textContent = store.key ? store.key.address : t("computer.noKey");
    this.forgetButton.textContent = t("key.forget");
    show(this.forgetButton, !!store.key);
    this.checkTitle.textContent = t("computer.checkTitle");
    this.checkHelp.textContent = t("computer.checkHelp");
  }
}
