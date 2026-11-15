// The window: header (website, chain, language, theme), key box, tabs, the
// three pages, the status line and the install-check overlay.
import { closePing, setTab, store, subscribe, type Tab } from "../app";
import { h } from "../dom";
import { getLanguage, LANGUAGES, msgParts, NAMES, onLanguage, setLanguage, t, type Language } from "../i18n";
import { setTheme, storedTheme, type Theme } from "../theme";
import { noteParts, partsNodes, show } from "./common";
import { ComputerView } from "./computer";
import { GrantsView } from "./grants";
import { KeyView } from "./key";
import { RequestView } from "./request";

export class Shell {
  readonly root = h("div", { class: "shell" });
  private title = h("h1", {});
  private site = h("p", { class: "muted small site", "data-testid": "site-line" });
  private tagline = h("p", { class: "muted small" });
  private dev = h("p", { class: "warning small" });
  private language = h("select", { "data-testid": "language" });
  private theme = h("select", { "data-testid": "theme" });
  private tabs = new Map<Tab, HTMLButtonElement>();
  private key = new KeyView();
  private request = new RequestView();
  private grants = new GrantsView();
  private computer = new ComputerView();
  private status = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "status" });
  private ping = h("div", { class: "overlay", "data-testid": "ping" });

  constructor() {
    // Each language is named in its own language (the one place another language shows).
    for (const language of LANGUAGES) this.language.appendChild(h("option", { value: language, lang: language, "data-raw": "" }, NAMES[language]));
    this.language.value = getLanguage();
    this.language.addEventListener("change", () => setLanguage(this.language.value as Language));
    for (const theme of ["auto", "light", "dark"] as const) this.theme.appendChild(h("option", { value: theme }));
    this.theme.value = storedTheme();
    this.theme.addEventListener("change", () => setTheme(this.theme.value as Theme));
    const nav = h("nav", { class: "tabs", role: "tablist" });
    for (const tab of ["request", "grants", "computer"] as const) {
      const button = h("button", { type: "button", role: "tab", class: "tab", onclick: () => setTab(tab), "data-testid": `tab-${tab}` });
      this.tabs.set(tab, button);
      nav.appendChild(button);
    }
    this.root.append(
      h(
        "header",
        { class: "header" },
        h("div", { class: "row wrap" }, this.title, h("span", { class: "spacer" }), h("div", { class: "row settings" }, this.language, this.theme)),
        this.site,
        this.tagline,
        this.dev,
      ),
      this.key.root,
      nav,
      h("main", {}, this.request.root, this.grants.root, this.computer.root),
      this.status,
      this.ping,
    );
    subscribe(() => this.update());
    onLanguage(() => this.update());
    this.update();
  }

  update(): void {
    const info = store.info;
    this.title.textContent = t("app.title");
    const api = store.link?.api ?? info?.defaultApi ?? "";
    const official = store.link ? store.link.official : true;
    this.site.replaceChildren(
      h("span", {}, t("app.website", { api })),
      official ? "" : h("strong", { class: "warning-inline" }, t("app.notOfficial")),
      info ? h("span", {}, t("app.chain", { chainId: info.chainId })) : "",
      info ? h("span", {}, t("app.rpc", { rpc: info.rpc })) : "",
    );
    this.tagline.textContent = t("app.tagline");
    this.dev.textContent = t("app.development");
    show(this.dev, !!info?.development);
    this.language.value = getLanguage();
    const labels: Record<Theme, string> = { auto: t("theme.auto"), light: t("theme.light"), dark: t("theme.dark") };
    [...this.theme.options].forEach((option) => (option.textContent = labels[option.value as Theme]));
    this.theme.setAttribute("aria-label", t("settings.theme"));
    this.language.setAttribute("aria-label", t("settings.language"));
    for (const [tab, button] of this.tabs) {
      button.textContent = tab === "computer" ? t(info?.mobile ? "tabs.device" : "tabs.computer") : t(`tabs.${tab}`);
      button.setAttribute("aria-selected", String(store.tab === tab));
      button.classList.toggle("active", store.tab === tab);
    }
    show(this.request.root, store.tab === "request");
    show(this.grants.root, store.tab === "grants");
    show(this.computer.root, store.tab === "computer");
    this.key.update();
    this.request.update();
    this.grants.update();
    this.computer.update();
    this.status.replaceChildren(...partsNodes(noteParts(store.status)));
    this.status.className = `status ${store.status?.tone ?? "info"}`;
    this.updatePing();
  }

  private updatePing(): void {
    const ping = store.ping;
    show(this.ping, !!ping);
    if (!ping) {
      this.ping.replaceChildren();
      return;
    }
    const text =
      ping.phase === "sending"
        ? { text: t("ping.sending", { api: ping.api || store.link?.api || store.info?.defaultApi || "" }), raw: [] }
        : ping.phase === "linked" && ping.result
          ? { text: t("ping.linked"), raw: [] }
          : ping.message
            ? (() => {
                const parts = msgParts(ping.message);
                return { text: t("ping.failed", { message: parts.text }), raw: parts.raw };
              })()
            : { text: t("ping.failed", { message: "" }), raw: [] };
    this.ping.replaceChildren(
      h(
        "div",
        { class: "card modal-card" },
        h("h2", {}, t("ping.title")),
        h("p", { "data-testid": "ping-text", class: ping.phase === "failed" ? "error-text" : "" }, partsNodes(text)),
        ping.result ? h("p", { class: "muted small" }, t("ping.details", { ...ping.result })) : null,
        ping.countdown ? h("p", { class: "muted small" }, t("ping.closes", { seconds: ping.countdown })) : null,
        h("div", { class: "row end" }, h("button", { type: "button", onclick: () => closePing(), "data-testid": "ping-close", disabled: ping.phase === "sending" }, t("common.close"))),
      ),
    );
  }
}
