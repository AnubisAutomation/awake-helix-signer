// Shared fixtures of the page tests: a scripted backend (the Tauri invoke
// layer mocked) whose answers have the shapes src-tauri/src/views.rs sends,
// including coded messages and the structured summary.
import type { CommandError, GrantRow, Listing, Msg, RuleSummary, SessionView, Summary, Transport } from "../src/api";

export function m(code: string, text: string, params: Msg["params"] = {}): Msg {
  return { code, params, text };
}

/** A website error answer as the core passes it on (code "website"). */
export function site(code: string, zh: string, en: string, params: Record<string, unknown> = {}, status = 400): Msg {
  return { code: "website", params: {}, text: en || zh, site: { status, code, params, zh, en } };
}

export function grantSummary(calls: number, perCall = "10", official = true): Summary {
  return {
    kind: "grant",
    signerVersion: "0.5.2",
    website: API,
    officialWebsite: official,
    chainId: 6714,
    rpcUrl: "https://rpc.anubispace.org",
    development: false,
    owner: OWNER,
    transaction: "",
    balance: "1.5 DAI",
    grant: {
      delegates: true,
      delegate: "0xA37eBF54868c76B52A35741859d9835609d48695",
      movesFrom: "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A",
      originRules: true,
      codeHashVerified: true,
      sessionKey: "0x70F6C48E3AfC7E499fF2329d698474Fd293626Bc",
      botScript: "dai-power",
      botId: "7c1f9e0e-41a8-4d6e-9d15-2f7d9a0e9c11",
      grantId: "0x" + "9f".repeat(32),
      validAfter: 1794000000,
      validUntil: 1794816462,
      remainingCalls: calls,
      rules: [
        {
          index: 1, kind: 0, method: "approve", target: "0x6B175474E89094C44Da98b954EedeAC495271d0F", targetName: "DAI",
          spender: "0x8a1b2C3d4E5f60718293A4b5C6d7E8f901234567", spenderName: "PowerLedger", swap: null, unit: "DAI", decimals: 18,
          maxPerCall: perCall, maxPerDay: "10", counted: false, activationDai: null, deadlineSeconds: null, floor: null, paysOwner: false,
        },
        {
          index: 2, kind: 3, method: "swapExactTokensForTokens", target: "0x1111111111111111111111111111111111111111", targetName: "HelixRouter",
          spender: null, spenderName: "",
          swap: { tokenIn: "0x6B175474E89094C44Da98b954EedeAC495271d0F", tokenInName: "DAI", tokenOut: "0x4d1D808a081FdAC440703B3765fC61f8028C06B8", tokenOutName: "LGNS", priceFloor: "0.05" },
          unit: "DAI", decimals: 18, maxPerCall: "5", maxPerDay: "20", counted: false, activationDai: null, deadlineSeconds: 900, floor: null, paysOwner: false,
        },
        {
          index: 3, kind: 9, method: "withdrawLocked", target: "0x2222222222222222222222222222222222222222", targetName: "Turbine",
          spender: null, spenderName: "", swap: null, unit: "lock IDs", decimals: 0, maxPerCall: "1", maxPerDay: "4", counted: false, activationDai: "2", deadlineSeconds: null,
          floor: null, paysOwner: false,
        },
        ...originRules(4),
      ],
      customized: ["remainingCalls", "rules[0].maxPerCall"],
    },
    revoke: null,
  };
}

/** Origin rules (version 2 Diamond) as the core summarizes them, numbered from `first`. */
export function originRules(first: number): RuleSummary[] {
  const turbo = "0x0664F1369209677FEcb279F5EC3Df1E53a22212e";
  const dai = "0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14";
  const lgns = "0x4D1D808a081FdAc440703b3765FC61f8028C06B8";
  const base = { spender: null, spenderName: "", swap: null, floor: null, counted: false, activationDai: null, deadlineSeconds: null, paysOwner: false };
  return [
    {
      ...base, index: first, kind: 10, method: "participate", target: turbo, targetName: "New Turbo 2.5x", unit: "DAI", decimals: 18,
      maxPerCall: "100", maxPerDay: "100", deadlineSeconds: 600,
      floor: { tokenIn: dai, tokenInName: "DAI", tokenOut: lgns, tokenOutName: "LGNS", priceFloor: "10" },
    },
    {
      ...base, index: first + 1, kind: 11, method: "activate", target: turbo, targetName: "New Turbo 2.5x", unit: "LGNS", decimals: 9,
      maxPerCall: "500", maxPerDay: "500", activationDai: "50", deadlineSeconds: 600,
      floor: { tokenIn: dai, tokenInName: "DAI", tokenOut: dai, tokenOutName: "DAI", priceFloor: "0.9" },
    },
    {
      ...base, index: first + 2, kind: 18, method: "claim", target: "0x3f403751975e1EB06d95901f7FF246513444E71F", targetName: "Burn Fixed",
      unit: "calls", decimals: 0, maxPerCall: "1", maxPerDay: "24", counted: true,
    },
    {
      ...base, index: first + 3, kind: 25, method: "silence", target: "0x92B53785090F6FE0717Ca3cF5dB8f8040d3B070b", targetName: "Origin Turbine",
      unit: "DAI", decimals: 18, maxPerCall: "10", maxPerDay: "10", deadlineSeconds: 300, paysOwner: true,
    },
  ];
}

export function revokeSummary(grantId: string, redelegates = false): Summary {
  return {
    ...grantSummary(0),
    kind: "revoke",
    grant: null,
    revoke: {
      method: "revokePolicyGrant(bytes32)", grantId, grantKind: "policy", delegation: redelegates ? "" : "0x2C4a2bcA2C4E9b9Cb5D1D2c7a1fb51e6F5d6Fa8E",
      redelegates, delegate: "0x2C4a2bcA2C4E9b9Cb5D1D2c7a1fb51e6F5d6Fa8E", delegateName: "Helix7702Account",
    },
  };
}

export function refused(msg: Msg): CommandError {
  return { kind: "refused", message: msg.text, msg };
}

export function grantRow(grantId: string, status: string, extra: Partial<GrantRow> = {}): GrantRow {
  return {
    grantId, kind: "policy", status, key: "0x70f6c48e3afc7e499ff2329d698474fd293626bc",
    keyOrigin: "hosted", bot: "dai-power #12 (running)", botState: "running", botScript: "dai-power", botId: "12",
    validUntil: 1794816462, remainingCalls: 254, revocable: true, active: status === "active",
    delegation: "helix", notRevocableReason: "", ...extra,
  };
}

export const API = "https://anubis.sivilization.com";
export const OWNER = "0x814CEceE4ab7a2c37ED2F2C67bef5B325Ac53bDF";

export function session(calls: number, perCall = "10"): SessionView {
  return {
    kind: "grant",
    confirmWord: "AUTHORIZE",
    summary: `Owner: ${OWNER}\nCalls: at most ${calls} bot operations in total`,
    summaryData: grantSummary(calls, perCall),
    editor: {
      validUntil: 1794816462,
      remainingCalls: calls,
      bounds: { validUntil: { min: 1794000000, max: 1801000000 }, remainingCalls: { min: 2, max: 4096 } },
      rules: [
        { index: 0, kind: 0, method: "approve", targetName: "DAI", counted: false, unit: "DAI", decimals: 18, maxPerCall: perCall, maxPerDay: "10", bounds: { maxPerCall: { min: "10", max: "20" }, maxPerDay: { min: "10", max: "40" } } },
        { index: 1, kind: 18, method: "claim", targetName: "Burn Fixed", counted: true, unit: "calls", decimals: 0, maxPerCall: "1", maxPerDay: "24" },
      ],
    },
  };
}

export function listing(revoked: string[] = []): Listing {
  const row = (grantId: string, status: string) => ({
    grantId, kind: "policy", status: revoked.includes(grantId) ? "revoked" : status, key: "0x70f6c48e3afc7e499ff2329d698474fd293626bc",
    keyOrigin: "hosted", bot: "dai-power #12 (running)", botState: "running", botScript: "dai-power", botId: "12", validUntil: 1794816462, remainingCalls: 254,
    revocable: !revoked.includes(grantId), active: !revoked.includes(grantId) && status === "active",
    delegation: "helix", notRevocableReason: "",
  });
  return { owner: OWNER.toLowerCase(), rows: [row("0xa1", "active"), row("0xb2", "active"), row("0xc3", "expired")], scanComplete: true, scanPercent: 100, truncated: false };
}

export class FakeBackend implements Transport {
  calls: [string, Record<string, unknown> | undefined][] = [];
  handlers = new Map<string, ((payload: unknown) => void)[]>();
  key: string | null = null;
  revoked: string[] = [];
  pending: string[] = [];
  title = "";
  answers: Record<string, (args: Record<string, unknown>) => unknown> = {
    app_info: () => ({ version: "0.5.2", os: "linux", arch: "x86_64", mobile: false, chainId: 6714, rpc: "https://rpc.anubispace.org", defaultApi: API, development: false, selftest: false, launchedForPing: false }),
    initial_link: () => null,
    open_link: ({ url }) => {
      const value = String(url);
      if (value.includes("api=https://evil")) throw refused(m("link.foreignSite", "This link points to https://evil.example, which is not the official Anubis Automation website (https://anubis.sivilization.com). It was refused. If you really run your own instance, pass --allow-api https://evil.example.", { site: "https://evil.example", official: API }));
      const action = /^(?:anubisauto|awakehelix):\/\/(\w+)/i.exec(value)![1];
      return { action, api: API, official: true };
    },
    close_request: () => null,
    load_key: ({ source }) => {
      const input = source as { kind: string; secret?: string };
      if (input.kind === "privateKey" && input.secret !== "0x" + "11".repeat(32)) throw refused(m("key.privateKeyFormat", "A private key is 64 hexadecimal characters (optionally with 0x)."));
      this.key = OWNER;
      return { address: OWNER, source: input.kind, derivationPath: null };
    },
    key_status: () => (this.key ? { address: this.key, source: "privateKey", derivationPath: null } : null),
    forget_key: () => {
      this.key = null;
      return null;
    },
    prepare_request: () => {
      const line = m("log.fetchingPlan", `Fetching plan from ${API} ...`, { api: API });
      this.emit("signer://log", { scope: "request", line: line.text, msg: line });
      return session(256);
    },
    customize: ({ request }) => {
      const body = request as { remainingCalls?: number; rules?: { maxPerCall: string }[] };
      if (!("remainingCalls" in body)) return session(256);
      if (body.remainingCalls! > 4096) {
        const en = "The call count must be between 2 (the operations of one run) and 4096 (4 per rule per day for 31 days, 4096 at most).";
        const zh = "剩餘呼叫次數必須介於 2（一次執行需要的操作數）與 4096（每條規則每天 4 次 × 31 天，最多 4096）之間。";
        throw { kind: "customize", message: en, msg: site("bounds.calls", zh, en, { min: 2, max: 4096, perRuleDay: 4, days: 31, cap: 4096 }) } satisfies CommandError;
      }
      return session(body.remainingCalls!, body.rules?.[0]?.maxPerCall ?? "10");
    },
    sign: ({ word }) => {
      if (word !== "AUTHORIZE") throw refused(m("app.mustType", "Type AUTHORIZE exactly to sign.", { word: "AUTHORIZE" }));
      this.key = null;
      return { txHash: "0x" + "ab".repeat(32), block: 101, reported: true, reportMessage: "" };
    },
    grants_load: () => listing(this.revoked),
    grants_prepare: ({ grantIds }) => {
      this.pending = (grantIds as string[] | null) ?? listing(this.revoked).rows.filter((row) => row.active).map((row) => row.grantId);
      return { count: this.pending.length, summaries: this.pending.map((id) => `Grant ID:    ${id} (policy grant)`), summaryData: this.pending.map((id) => revokeSummary(id)) };
    },
    grants_confirm: () => {
      const lines = this.pending.map((id, index) => {
        this.revoked.push(id);
        this.emit("signer://progress", { done: index + 1, total: this.pending.length });
        return m("app.revoked", `Revoked ${id} in transaction 0x${index} (block ${102 + index}).`, { grant: id, tx: `0x${index}`, block: String(102 + index) });
      });
      const total = this.pending.length;
      this.pending = [];
      return { done: total, total, cancelled: false, listing: listing(this.revoked), lines };
    },
    grants_cancel: () => {
      this.pending = [];
      return null;
    },
    setup_status: () => ({ os: "linux", mobile: false, handler: "anubisauto-signer-app-handler.desktop", command: null, canRegister: true, canInstallCli: true, cliPlaces: ["/home/u/.local/bin"], firstRun: false }),
    ping: () => ({ version: "0.5.2", os: "linux", arch: "x86_64", api: API }),
    set_title: ({ title }) => {
      this.title = String(title);
      return null;
    },
  };

  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push([command, args]);
    const answer = this.answers[command];
    if (!answer) throw { kind: "error", message: `no fake for ${command}`, msg: m("io", `no fake for ${command}`) } satisfies CommandError;
    return answer(args ?? {}) as T;
  }
  async listen<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
    const list = this.handlers.get(event) ?? [];
    list.push(handler as (payload: unknown) => void);
    this.handlers.set(event, list);
    return () => undefined;
  }
  emit(event: string, payload: unknown): void {
    (this.handlers.get(event) ?? []).forEach((handler) => handler(payload));
  }
  commands(): string[] {
    return this.calls.map(([command]) => command);
  }
}

export const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
export const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.querySelector<T>(`[data-testid="${id}"]`)!;
export const type = (id: string, value: string) => {
  const input = $<HTMLInputElement>(id);
  input.value = value;
  input.dispatchEvent(new Event("input"));
};
export const click = async (id: string) => {
  $<HTMLButtonElement>(id).click();
  for (let i = 0; i < 5; i++) await settle();
};

