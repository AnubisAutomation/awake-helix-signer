// Every page and state in each of the six languages: nothing on screen may
// come from another language. The page is driven once into each state, then
// the language is switched at runtime and the same screen is audited again,
// so this also proves that a switch re-renders what is already shown (the
// summary, the editor, the logs, errors from the core and the website, the
// grants list, dialogs and the window title).
import { setTransport, type Msg } from "../src/api";
import { handleUrl, start, store } from "../src/app";
import { en } from "../src/i18n/en";
import { audit, deniedWords, type Leak } from "../src/i18n/audit";
import { DICTIONARIES, LANGUAGES, msgText, placeholders, setLanguage, type Language } from "../src/i18n";
import { initialGrants, initialRequest } from "../src/machines";
import { Shell } from "../src/views/shell";
import { $, API, click, FakeBackend, grantRow, listing, m, OWNER, revokeSummary, settle, site, type } from "./fixtures";

let backend: FakeBackend;

beforeEach(async () => {
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open");
  };
  setLanguage("en");
  Object.assign(store, { tab: "request", link: null, key: null, request: initialRequest, grants: initialGrants, logs: { request: [], grants: [] }, status: null, ping: null });
  store.keyForm = { source: "keystore", path: "", json: "", fileName: "", index: "0" };
  backend = new FakeBackend();
  setTransport(backend);
  document.body.replaceChildren(new Shell().root);
  await start();
  await settle();
});

afterEach(() => setLanguage("en"));

/** Audit the whole document in every language (switching at runtime), English last. */
function expectEveryLanguage(what: string): void {
  const leaks: Leak[] = [];
  for (const language of [...LANGUAGES.filter((item) => item !== "en"), "en" as Language]) {
    setLanguage(language);
    leaks.push(...audit(document.body, language));
  }
  expect(leaks, `${what}:\n${leaks.map((leak) => `${leak.language} ${leak.reason}${leak.word ? ` (${leak.word})` : ""}: ${leak.text}`).join("\n")}`).toEqual([]);
}

async function unlockPrivateKey(): Promise<void> {
  $<HTMLInputElement>("key-source-privateKey").click();
  type("key-private", "0x" + "11".repeat(32));
}

async function verifiedRequest(): Promise<void> {
  await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
  await unlockPrivateKey();
  await click("request-load");
}

describe("every screen follows the selected language", () => {
  it("request: summary, editor, a website refusal and the progress log", async () => {
    await verifiedRequest();
    // Progress lines of the core, with nested messages (gas estimate, a website answer).
    const how = m("gas.authorizationList", "eth_estimateGas with authorizationList");
    backend.emit("signer://log", { scope: "request", line: "", msg: m("log.gas", "Gas limit 385000 (…); maximum fee 0.0077 DAI.", { gas: "385000", how, fee: "0.0077 DAI" }) });
    const untranslated = site("tx.newCode", "新的網站訊息。", "A message this app has no translation for.", {}, 409);
    backend.emit("signer://log", { scope: "request", line: "", msg: m("log.reportFailed", "The website did not accept the report", { error: untranslated }) });
    backend.emit("signer://log", { scope: "request", line: "", msg: m("plan", "Plan calldata is not hex.") });
    // The website refuses an edit: its own code, translated here.
    type("edit-calls", "9999");
    await click("edit-apply");
    expect($("edit-error").textContent).not.toBe("");
    expect($("summary").children.length).toBeGreaterThan(20);
    expectEveryLanguage("request with summary, editor and errors");

    // The calls label and its help in each language.
    const labels = new Set<string>();
    for (const language of LANGUAGES) {
      setLanguage(language);
      const field = $("edit-calls").closest("label")!;
      labels.add(field.querySelector(".field-label")!.textContent!);
      expect($("edit-calls-help").textContent).toBe(DICTIONARIES[language]["editor.callsHelp"]);
      // The website's refusal of the edit stays, in this language.
      expect($("edit-error").textContent).toContain(DICTIONARIES[language]["site.bounds.calls"].split("{")[0]);
    }
    expect([...labels]).toEqual(LANGUAGES.map((language) => DICTIONARIES[language]["editor.calls"]));
  });

  it("request: refusals of the core and the backend, then the signed result", async () => {
    await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x1234");
    await click("request-load");
    expect($("status").textContent).toContain("A private key is 64 hexadecimal characters");
    expectEveryLanguage("refused key");

    backend.answers.prepare_request = () => {
      throw { kind: "refused", message: "x", msg: m("flow.wrongKey", "Wrong key", { key: OWNER, owner: "0x0000000000000000000000000000000000000001" }) };
    };
    await unlockPrivateKey();
    await click("request-load");
    expectEveryLanguage("wrong key");

    backend.answers.prepare_request = () => {
      // A plain plan error: a translated headline, the English detail shown apart.
      throw { kind: "refused", message: "Grant has no bot ID.", msg: m("flow.grantFailed", "Grant 0x1: Grant has no bot ID.", { grant: "0x1", cause: m("plan", "Grant has no bot ID.") }) };
    };
    await unlockPrivateKey();
    await click("request-load");
    expect($("status").querySelector("[data-raw]")?.textContent).toBe("Grant has no bot ID.");
    expectEveryLanguage("generic plan error with English detail");

    backend.answers.prepare_request = new FakeBackend().answers.prepare_request;
    await unlockPrivateKey();
    await click("request-load");
    type("confirm-word", "AUTHORIZE");
    await click("sign");
    expect(store.request.phase).toBe("done");
    expectEveryLanguage("signed result");
  });

  it("refused links and the discard dialog", async () => {
    await handleUrl("awakehelix://sign?plan=xxxxxxxxxxxxxxxxxxxxxxxx&api=https://evil.example");
    expectEveryLanguage("foreign website");
    await handleUrl("https://example.com");
    expectEveryLanguage("not an awakehelix link");
    await verifiedRequest();
    const opening = handleUrl(`awakehelix://revoke?plan=${"R".repeat(32)}`);
    await settle();
    expect($("confirm-dialog").hasAttribute("open")).toBe(true);
    expectEveryLanguage("discard dialog");
    await click("confirm-no");
    await opening;
  });

  it("grants: every status, notes, scan, a pending revocation and its log", async () => {
    const rows = [
      grantRow("0xa1", "active"),
      grantRow("0xa2", "not_yet_valid", { botState: "stopped" }),
      grantRow("0xa3", "expired", { botState: "deleted", revocable: false }),
      grantRow("0xa4", "revoked", { botState: "none", botScript: "", botId: "", revocable: false }),
      grantRow("0xa5", "exhausted", { botState: "unknown", botScript: "", remainingCalls: 0, revocable: false }),
      grantRow("0xa6", "inactive", { active: true, delegation: "none" }),
      grantRow("0xa7", "inactive", { revocable: false, delegation: "other", notRevocableReason: "otherDelegation" }),
      grantRow("0xa8", "unavailable", { revocable: false, remainingCalls: null }),
      grantRow("0xa9", "missing", { revocable: false, remainingCalls: null, validUntil: null }),
      grantRow("0xaa", "frozen_by_dao", { revocable: false }),
    ];
    backend.answers.grants_load = () => ({ ...listing(), rows, scanComplete: false, scanPercent: 40, truncated: true, refreshing: true });
    await handleUrl("awakehelix://grants");
    await unlockPrivateKey();
    await click("grants-load");
    expect(document.querySelectorAll('[data-testid="grant-row"]')).toHaveLength(rows.length);
    expect($("grants-scan").textContent).toContain("Updating the statuses from the chain");
    expectEveryLanguage("grants list with every status");

    backend.answers.grants_prepare = () => ({ count: 2, summaries: ["", ""], summaryData: [revokeSummary("0xa1"), revokeSummary("0xa6", true)] });
    await click("grants-revoke-all");
    expect($("grants-log").textContent).not.toBe("");
    expectEveryLanguage("pending revocation with summaries");

    backend.answers.grants_confirm = () => {
      throw { kind: "refused", message: "x", msg: m("app.revokedBefore", "x", { cause: site("revoke.pending", "撤銷交易尚未確認。", "The revocation transaction is not confirmed yet.", {}, 409), done: "1", total: "2" }) };
    };
    type("grants-word", "REVOKE");
    await click("grants-confirm");
    expectEveryLanguage("a failed revocation");
  });

  it("grants: the website's errors by code", async () => {
    backend.answers.grants_load = () => {
      throw { kind: "refused", message: "x", msg: site("grants.unreadable", "無法讀取鏈上 Grant，請稍後再試。", "Cannot read the grants on chain; try again later.", {}, 503) };
    };
    await handleUrl("awakehelix://grants");
    await unlockPrivateKey();
    await click("grants-load");
    for (const language of LANGUAGES) {
      setLanguage(language);
      expect($("status").textContent).toContain(DICTIONARIES[language]["site.grants.unreadable"]);
    }
    expectEveryLanguage("grants unreadable");
  });

  it("grants: a busy or unreachable website, also while signing in", async () => {
    const SITE = "https://anubis.sivilization.com";
    const busy = m("website.busy", `The website ${SITE} is busy and did not answer in time (timed out); try again in a moment.`, { site: SITE, detail: "timed out" });
    const unreachable = m("website.unreachable", `Cannot reach the website ${SITE} (dns error); check the internet connection and try again.`, {
      site: SITE,
      detail: "dns error",
    });
    const cases: [Msg, string, string][] = [
      [m("login.failed", `Signing in to the website failed. ${busy.text}`, { cause: busy }), "core.login.failed", "core.website.busy"],
      [m("login.failed", `Signing in to the website failed. ${unreachable.text}`, { cause: unreachable }), "core.login.failed", "core.website.unreachable"],
      [busy, "core.website.busy", "core.website.busy"],
    ];
    await handleUrl("awakehelix://grants");
    await unlockPrivateKey();
    for (const [msg, outer, inner] of cases) {
      backend.answers.grants_load = () => {
        throw { kind: "refused", message: msg.text, msg };
      };
      await click("grants-load");
      const shown = new Set<string>();
      for (const language of LANGUAGES) {
        setLanguage(language);
        const table = DICTIONARIES[language] as Record<string, string>;
        const status = $("status").textContent!;
        // The step (signing in) and the cause, both translated; the site is data.
        expect(status, language).toContain(table[outer].split("{")[0].trim());
        expect(status, language).toContain(table[inner].split("{")[0].trim());
        expect(status, language).toContain(SITE);
        shown.add(status);
      }
      expect(shown.size).toBe(LANGUAGES.length);
      setLanguage("en");
      expectEveryLanguage(msg.code);
    }
  });

  it("this computer, the save dialog and the forget dialog", async () => {
    await handleUrl("awakehelix://grants");
    await unlockPrivateKey();
    await click("grants-load");
    await click("tab-computer");
    expectEveryLanguage("this computer with a key");
    backend.answers.register_links = () => m("app.linksRegistered", "awakehelix:// links now open this app.");
    await click("setup-register");
    expectEveryLanguage("links registered");
    // Saving a key read from a private key as an encrypted keystore.
    $("key-save").click();
    await settle();
    expect($("save-dialog").hasAttribute("open")).toBe(true);
    type("save-password", "short");
    $("save-confirm").click();
    expectEveryLanguage("save dialog with a problem");
    $("save-cancel").click();
    await settle();
    const forgetting = click("setup-forget");
    await settle();
    expectEveryLanguage("forget dialog");
    $("confirm-yes").click();
    await forgetting;
    await settle();
    expectEveryLanguage("key wiped");
  });

  it("install check overlay, failed and linked", async () => {
    backend.answers.ping = () => {
      throw { kind: "refused", message: "x", msg: m("ping.refused", "x", { error: site("check.used", "此驗證已完成；請回到網站查看。", "This check is already confirmed.", {}, 409) }) };
    };
    await handleUrl(`awakehelix://ping?token=${"P".repeat(32)}`);
    expectEveryLanguage("failed install check");
    backend.answers.ping = () => ({ version: "0.5.2", os: "linux", arch: "x86_64", api: API });
    await handleUrl(`awakehelix://ping?token=${"P".repeat(32)}`);
    expectEveryLanguage("linked install check");
  });

  it("the window title follows the language", async () => {
    for (const language of LANGUAGES) {
      setLanguage(language);
      await settle();
      expect(backend.title).toBe(`${DICTIONARIES[language]["app.title"]} 0.5.2`);
      expect(document.title).toBe(DICTIONARIES[language]["app.title"]);
    }
  });
});

describe("the audit itself", () => {
  it("catches English left on a Japanese screen", () => {
    document.body.replaceChildren(Object.assign(document.createElement("p"), { textContent: en["grants.help"] }));
    const leaks = audit(document.body, "ja");
    expect(leaks.map((leak) => leak.reason)).toContain("not in the table");
    expect(leaks.some((leak) => leak.reason === "English word")).toBe(true);
    // Before this release the editor's label was English data in other languages too.
    expect(deniedWords("ja").has("calls")).toBe(true);
  });

  it("lets data through and marked raw details", () => {
    setLanguage("ko");
    document.body.innerHTML = `<p>0x814C…3bDF</p><p>2026/11/15 14:00:00</p><p><span data-raw>English detail</span></p>`;
    expect(audit(document.body, "ko")).toEqual([]);
  });
});

// ------------------------------------------------- codes of the core and the backend

// The Rust sources of the core and the app backend, read as text (Node's
// own modules; the page's TypeScript setup has no Node types).
interface Fs {
  readdirSync(path: string): string[];
  statSync(path: string): { isDirectory(): boolean };
  readFileSync(path: string, encoding: "utf8"): string;
}
const node = (globalThis as unknown as { process: { cwd(): string; getBuiltinModule(name: "node:fs"): Fs } }).process;
const fs = node.getBuiltinModule("node:fs");

function rustFiles(dir: string): string[] {
  return fs.readdirSync(dir).flatMap((name) => {
    const path = `${dir}/${name}`;
    return fs.statSync(path).isDirectory() ? rustFiles(path) : name.endsWith(".rs") ? [path] : [];
  });
}

const RUST = [...rustFiles(`${node.cwd()}/../crates/helix-signer-core/src`), ...rustFiles(`${node.cwd()}/src-tauri/src`)].map((file) =>
  fs.readFileSync(file, "utf8"),
);

/** Every msg!("code", "template", ...) of the Rust sources, with its params. */
function rustCodes(): Map<string, string[]> {
  const codes = new Map<string, string[]>();
  for (const text of RUST) {
    const source = text
      .split("\n")
      .filter((line) => !line.trim().startsWith("//"))
      .join("\n");
    for (const found of source.matchAll(/msg!\(\s*"([\w.]+)"\s*,\s*"((?:[^"\\]|\\.)*)"/g)) {
      const params = [...found[2].replace(/\\u\{\w+\}/g, "").matchAll(/(?<!\{)\{(\w+)\}/g)].map((item) => item[1]);
      codes.set(found[1], [...new Set(params)].sort());
    }
  }
  return codes;
}

describe("codes of the core and the backend", () => {
  const codes = rustCodes();

  it("finds the codes", () => {
    expect(codes.size).toBeGreaterThan(90);
    expect(codes.get("flow.wrongKey")).toEqual(["key", "owner"]);
  });

  it.each(LANGUAGES)("%s translates every code, naming only values the code carries", (language) => {
    const table = DICTIONARIES[language] as Record<string, string>;
    for (const [code, params] of codes) {
      const text = table[`core.${code}`];
      expect(text, `${language}: core.${code}`).toBeTruthy();
      for (const name of placeholders(text)) expect(params, `${language}: core.${code} {${name}}`).toContain(name);
    }
  });

  it("has no translation for a code that no longer exists", () => {
    const stale = Object.keys(en).filter((key) => key.startsWith("core.") && !codes.has(key.slice(5)));
    expect(stale).toEqual([]);
  });

  it("translates the website's codes the app shows", () => {
    for (const code of [
      "auth.required", "plan.notFound", "plan.used", "plan.replaced", "plan.finished", "plan.expired", "plan.notCustomizable", "plan.botActive",
      "plan.notFetched", "plan.reportClosed", "plan.doneByOther", "bounds.tooFar", "bounds.expiry", "bounds.calls", "bounds.perCall", "bounds.perDay",
      "bounds.notDecimal", "bounds.notPositive", "bounds.notWhole", "grants.unreadable", "grant.notFound", "grant.revoked", "grant.missing",
      "grant.otherDelegation", "chain.unreadable", "check.notFound", "check.used", "check.expired", "server.busy",
    ]) {
      expect(en, code).toHaveProperty([`site.${code}`]);
    }
  });

  it("renders a website message by its code, else in the website's own languages", () => {
    const bounds = site("bounds.perDay", "每日上限…", "Rule 1 (DAI): the per-day cap…", { rule: 1, unit: "lock IDs", min: "10", max: "40", factor: 4 });
    setLanguage("ja");
    expect(msgText(bounds)).toBe("ルール 1（ロック ID）：1 日あたり上限は 10（戦略の必要量と 1 回あたり上限を下回らない）から 40（必要量の 4 倍）の間にしてください。");
    const expiry = site("bounds.expiry", "到期時間…", "The expiry…", { min: 1794000000, next: 1793996400, max: 1801000000, days: 90 });
    setLanguage("es");
    expect(msgText(expiry)).toContain("UTC");
    expect(msgText(expiry)).not.toContain("1794000000");
    const unknown = site("tx.brandNew", "新的訊息。", "A brand-new message.");
    const shown: Record<string, string> = {};
    for (const language of LANGUAGES) {
      setLanguage(language);
      shown[language] = msgText(unknown);
    }
    expect(shown["zh-Hant"]).toBe("新的訊息。");
    expect(shown.en).toBe("A brand-new message.");
    expect(shown.ja).toBe(`${DICTIONARIES.ja["site.untranslated"]} A brand-new message.`);
    expect(shown["zh-Hans"]).toBe(`${DICTIONARIES["zh-Hans"]["site.untranslated"]} 新的訊息。`);
    // An older website without codes: the text it sent.
    const old: Msg = { code: "website", params: {}, text: "x", site: { status: 410, code: "", params: {}, zh: "已過期", en: "" } };
    setLanguage("en");
    expect(msgText(old)).toBe("已過期");
  });
});
