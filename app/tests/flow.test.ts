// The whole page against a scripted backend (the Tauri invoke layer mocked):
// open link -> load key -> verified summary -> edit -> apply -> authorize,
// and My grants -> revoke one, revoke all, cancel; plus link refusals and the
// install check. The real backend is covered by the Rust tests and the
// end-to-end test.
import { setTransport } from "../src/api";
import { handleUrl, REFRESH_POLL_MS, start, store } from "../src/app";
import { setLanguage } from "../src/i18n";
import { initialGrants, initialRequest, REFRESH_POLLS } from "../src/machines";
import { Shell } from "../src/views/shell";
import { $, click, FakeBackend, listing, OWNER, settle, type } from "./fixtures";

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

describe("Request: link -> key -> summary -> edit -> authorize", () => {
  it("runs the whole authorization", async () => {
    await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
    expect($("request-heading").textContent).toBe("Authorize a hosted bot");
    expect($("request-load").hidden).toBe(false);

    // Private key: the secret leaves the field as soon as it is used.
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x" + "11".repeat(32));
    await click("request-load");
    expect($<HTMLInputElement>("key-private").value).toBe("");
    expect($("key-address").textContent).toContain(OWNER);
    expect($("summary").textContent).toContain("at most 256 bot operations");
    expect($("request-log").textContent).toContain("Fetching plan");
    expect(store.request.phase).toBe("verified");

    // Editing disables signing until the website re-planned and it was re-verified.
    type("edit-calls", "200");
    type("edit-call-0", "15");
    type("confirm-word", "AUTHORIZE");
    expect($<HTMLButtonElement>("sign").disabled).toBe(true);
    await click("edit-apply");
    const sent = backend.calls.find(([command]) => command === "customize")![1]!.request as Record<string, unknown>;
    expect(sent).toEqual({ validUntil: 1794816462, remainingCalls: 200, rules: [{ index: 0, maxPerCall: "15", maxPerDay: "10" }] });
    expect($("summary").textContent).toContain("at most 200 bot operations");
    type("confirm-word", "AUTHORIZE");
    expect($<HTMLButtonElement>("sign").disabled).toBe(false);

    await click("sign");
    expect(store.request.phase).toBe("done");
    expect($("result").textContent).toContain("block 101");
    expect($("result").textContent).toContain("The website was notified.");
    expect(store.key).toBeNull(); // wiped after signing
    expect(backend.commands()).toEqual(expect.arrayContaining(["open_link", "load_key", "prepare_request", "customize", "sign", "key_status"]));
  });

  it("keeps the plan when the website refuses an edit", async () => {
    await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x" + "11".repeat(32));
    await click("request-load");
    type("edit-calls", "9999");
    expect($("edit-error").textContent).toContain("outside the range");
    await click("edit-apply");
    expect(store.request.phase).toBe("verified");
    // The website's message, by its code, in the page's language.
    expect($("edit-error").textContent).toContain("Calls allowed must be between 2 (the operations of one run) and 4,096");
    // The same refused values are not sent again.
    await click("edit-apply");
    expect(backend.commands().filter((command) => command === "customize")).toHaveLength(1);
    // Back to the plan's values: signing is possible again.
    type("edit-calls", "256");
    type("confirm-word", "AUTHORIZE");
    expect($<HTMLButtonElement>("sign").disabled).toBe(false);
  });

  it("refuses a wrong confirmation word and a bad key", async () => {
    await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x1234");
    await click("request-load");
    expect($("status").textContent).toContain("Refused: A private key is 64 hexadecimal characters (optionally with 0x).");
    expect(store.request.phase).toBe("ready");
    type("key-private", "0x" + "11".repeat(32));
    await click("request-load");
    // A wrong word keeps Sign disabled; Enter says what to type and keeps the text.
    type("confirm-word", "AUTHORIZ");
    expect($<HTMLButtonElement>("sign").disabled).toBe(true);
    $<HTMLInputElement>("confirm-word").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await settle();
    expect($("status").textContent).toBe("Type AUTHORIZE exactly to sign.");
    expect($<HTMLInputElement>("confirm-word").value).toBe("AUTHORIZ");
    expect(backend.commands()).not.toContain("sign");
    // The Enter that commits an input method's composition never submits.
    type("confirm-word", "ＡＵＴＨＯＲＩＺＥ");
    $<HTMLInputElement>("confirm-word").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", isComposing: true }));
    await settle();
    expect(backend.commands()).not.toContain("sign");
    // Full-width or lower case: the word counts, and the canonical word is sent.
    expect($<HTMLButtonElement>("sign").disabled).toBe(false);
    await click("sign");
    expect(backend.calls.filter(([command]) => command === "sign").at(-1)![1]).toEqual({ word: "AUTHORIZE" });
  });

  it("refuses foreign websites, unknown links and asks before discarding a verified plan", async () => {
    await handleUrl("awakehelix://sign?plan=xxxxxxxxxxxxxxxxxxxxxxxx&api=https://evil.example");
    expect($("status").textContent).toBe("Refused link: This link points to https://evil.example, which is not the official Awake Helix website (https://anubis.sivilization.com). It was refused.");
    await handleUrl("https://anubis.sivilization.com");
    expect($("status").textContent).toBe("Only awakehelix:// links are accepted.");
    await handleUrl(`awakehelix://sign?plan=${"A".repeat(32)}`);
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x" + "11".repeat(32));
    await click("request-load");
    const opening = handleUrl(`awakehelix://revoke?plan=${"R".repeat(32)}`);
    await settle();
    await click("confirm-no");
    await opening;
    expect(store.request.phase).toBe("verified");
    const again = handleUrl(`awakehelix://revoke?plan=${"R".repeat(32)}`);
    await settle();
    await click("confirm-yes");
    await again;
    expect($("request-heading").textContent).toBe("Revoke a hosted-bot grant");
  });

  it("opens a pasted plan token as a sign link", async () => {
    type("paste-input", "T".repeat(30));
    await click("paste-open");
    expect(backend.calls.find(([command]) => command === "open_link")![1]).toEqual({ url: `awakehelix://sign?plan=${"T".repeat(30)}` });
  });
});

describe("My grants", () => {
  it("signs in, lists, revokes one after REVOKE, then revokes all", async () => {
    await handleUrl("awakehelix://grants");
    expect(store.tab).toBe("grants");
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x" + "11".repeat(32));
    await click("grants-load");
    expect(document.querySelectorAll('[data-testid="grant-row"]')).toHaveLength(3);
    expect($("status").textContent).toContain("3 grant(s) on");
    expect($<HTMLButtonElement>("grants-revoke-selected").disabled).toBe(true);

    $<HTMLInputElement>("grant-select-0xa1").click();
    await settle();
    expect($<HTMLButtonElement>("grants-revoke-selected").disabled).toBe(false);
    await click("grants-revoke-selected");
    expect($("grants-log").textContent).toContain("Grant ID: 0xa1 (policy grant)");
    // Confirm is enabled once the word is REVOKE (full-width / lower case count).
    expect($<HTMLButtonElement>("grants-confirm").disabled).toBe(true);
    type("grants-word", "revok");
    expect($<HTMLButtonElement>("grants-confirm").disabled).toBe(true);
    $<HTMLInputElement>("grants-word").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await settle();
    expect($("status").textContent).toBe("Type REVOKE exactly to sign.");
    expect($<HTMLInputElement>("grants-word").value).toBe("revok");
    type("grants-word", "ｒｅｖｏｋｅ");
    expect($<HTMLButtonElement>("grants-confirm").disabled).toBe(false);
    await click("grants-confirm");
    expect($("status").textContent).toBe("Revoked 1 of 1 grant(s).");
    expect(document.querySelector('[data-grant="0xa1"]')!.className).toContain("status-revoked");

    await click("grants-revoke-all");
    expect(backend.calls.filter(([command]) => command === "grants_prepare").at(-1)![1]).toEqual({ grantIds: null });
    await click("grants-cancel");
    expect($("status").textContent).toBe("Cancelled; nothing was signed.");
    await click("grants-revoke-all");
    type("grants-word", "REVOKE");
    await click("grants-confirm");
    expect($("status").textContent).toBe("Revoked 1 of 1 grant(s).");
    expect($<HTMLButtonElement>("grants-revoke-all").disabled).toBe(true);
  });

  it("labels every status, explains it, and offers Revoke only where revocable", async () => {
    const base = listing().rows[0];
    const rows = [
      { ...base, grantId: "0xd1", status: "inactive", revocable: true, active: true, delegation: "none" },
      { ...base, grantId: "0xd2", status: "inactive", revocable: false, active: false, delegation: "other", notRevocableReason: "otherDelegation" },
      { ...base, grantId: "0xd3", status: "unavailable", revocable: false, active: false, remainingCalls: null },
      { ...base, grantId: "0xd4", status: "missing", revocable: false, active: false, remainingCalls: null },
      { ...base, grantId: "0xd5", status: "frozen_by_dao", revocable: false, active: false },
    ];
    backend.answers.grants_load = () => ({ ...listing(), rows });
    await handleUrl("awakehelix://grants");
    $<HTMLInputElement>("key-source-privateKey").click();
    type("key-private", "0x" + "11".repeat(32));
    await click("grants-load");
    const statusOf = (id: string) => document.querySelector(`[data-grant="${id}"] .cell.status`)!.textContent;
    expect([statusOf("0xd1"), statusOf("0xd2"), statusOf("0xd3"), statusOf("0xd4")]).toEqual(["inactive", "inactive", "temporarily unreadable", "not installed"]);
    // An unknown (newer) status gets a neutral label and style; the list still renders.
    expect(statusOf("0xd5")).toBe("other status (frozen by dao)");
    expect(document.querySelector('[data-grant="0xd5"]')!.className).toContain("status-other");
    const notes = $("grants-notes").textContent!;
    expect(notes).toContain("it becomes active again if the account re-delegates");
    expect(notes).toContain("never overwrites someone else's delegation");
    expect(notes).toContain("Press Refresh to try again");
    expect(notes).toContain("never installed on chain");
    for (const id of ["0xd2", "0xd3", "0xd4", "0xd5"]) {
      $<HTMLInputElement>(`grant-select-${id}`).click();
      await settle();
      expect($<HTMLButtonElement>("grants-revoke-selected").disabled, id).toBe(true);
    }
    $<HTMLInputElement>("grant-select-0xd1").click();
    await settle();
    expect($<HTMLButtonElement>("grants-revoke-selected").disabled).toBe(false);
    expect($<HTMLButtonElement>("grants-revoke-all").disabled).toBe(false);
    // The retry hint points at the refresh button, which reloads the list.
    expect($("grants-load").textContent).toBe("Refresh");
    backend.answers.grants_load = () => listing();
    await click("grants-load");
    expect(document.querySelectorAll('[data-testid="grant-row"]')).toHaveLength(3);
    expect($("grants-notes").hidden).toBe(true);
  });

  it("shows the website's cached list and reads it again while the website refreshes it", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const flush = async () => {
        for (let i = 0; i < 10; i++) await vi.advanceTimersByTimeAsync(0);
      };
      let reads = 0;
      let fresh = 3;
      backend.answers.grants_load = () => {
        reads += 1;
        return { ...listing(), refreshing: reads < fresh };
      };
      await handleUrl("awakehelix://grants");
      $<HTMLInputElement>("key-source-privateKey").click();
      type("key-private", "0x" + "11".repeat(32));
      $("grants-load").click();
      await flush();
      expect(reads).toBe(1);
      // The cached list is shown at once, with a note.
      expect(document.querySelectorAll('[data-testid="grant-row"]')).toHaveLength(3);
      expect($("grants-scan").textContent).toContain("Updating the statuses from the chain");
      await vi.advanceTimersByTimeAsync(REFRESH_POLL_MS - 100);
      expect(reads).toBe(1);
      await vi.advanceTimersByTimeAsync(100);
      await flush();
      expect(reads).toBe(2);
      await vi.advanceTimersByTimeAsync(REFRESH_POLL_MS);
      await flush();
      expect(reads).toBe(3);
      expect($("grants-scan").textContent).not.toContain("Updating");
      await vi.advanceTimersByTimeAsync(REFRESH_POLL_MS * 5);
      expect(reads).toBe(3);

      // Still cached after every read: at most REFRESH_POLLS more, the list stays.
      reads = 0;
      fresh = Infinity;
      $("grants-load").click();
      await flush();
      await vi.advanceTimersByTimeAsync(REFRESH_POLL_MS * (REFRESH_POLLS + 5));
      await flush();
      expect(reads).toBe(1 + REFRESH_POLLS);
      expect(document.querySelectorAll('[data-testid="grant-row"]')).toHaveLength(3);
      expect($("grants-scan").textContent).toContain("Updating the statuses from the chain");
      expect(backend.commands().filter((command) => command === "grants_load")).toHaveLength(3 + 1 + REFRESH_POLLS);
    } finally {
      vi.useRealTimers();
    }
  });

  it("translates the new statuses in every language", async () => {
    const { LANGUAGES, setLanguage } = await import("../src/i18n");
    const { statusText } = await import("../src/views/grants");
    const seen = new Set<string>();
    for (const language of LANGUAGES) {
      setLanguage(language);
      const labels = ["inactive", "missing", "unavailable"].map(statusText);
      labels.forEach((label) => expect(label.trim(), language).not.toBe(""));
      seen.add(labels.join("|"));
      expect(statusText("brand_new"), language).toContain("brand new");
      expect(statusText("<img src=x>"), language).not.toContain("<");
    }
    expect(seen.size).toBe(LANGUAGES.length);
    setLanguage("en");
  });

  it("switches language everywhere", async () => {
    $<HTMLSelectElement>("language").value = "ja";
    $<HTMLSelectElement>("language").dispatchEvent(new Event("change"));
    expect($("tab-grants").textContent).toBe("マイ権限");
    expect($("grants-load").textContent).toBe("鍵を解錠して権限を読み込む");
  });
});

describe("install check", () => {
  it("answers a ping link in an overlay", async () => {
    await handleUrl(`awakehelix://ping?token=${"P".repeat(32)}`);
    expect($("ping-text").textContent).toContain("installed and linked");
    await click("ping-close");
    expect($("ping").hidden).toBe(true);
  });
});
