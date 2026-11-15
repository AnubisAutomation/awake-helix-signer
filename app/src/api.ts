// The only door to the Rust backend. Every command is listed here with the
// shapes the backend (src-tauri/src/views.rs) sends; tests and the browser
// preview swap the transport with setTransport().
import type { CustomizeRequest, EditorPlan } from "./editor";

/** A message of the core or the backend: a stable code, its values and the
 * English text the command line prints (the page translates `core.<code>`). */
export interface Msg {
  code: string;
  params: Record<string, string | Msg>;
  text: string;
  /** For code `website`: what the website answered. */
  site?: SiteText;
}

/** A website error answer: its own code and params (newer websites), its
 * Traditional Chinese text and its English text. */
export interface SiteText {
  status: number;
  code: string;
  params: Record<string, unknown>;
  zh: string;
  en: string;
}

/** The verified summary as data (helix_signer_core::Summary). */
export interface RuleSummary {
  index: number;
  kind: number;
  method: string;
  target: string;
  targetName: string;
  spender: string | null;
  spenderName: string;
  swap: { tokenIn: string; tokenInName: string; tokenOut: string; tokenOutName: string; priceFloor: string } | null;
  unit: string;
  decimals: number;
  maxPerCall: string;
  maxPerDay: string;
  activationDai: string | null;
  deadlineSeconds: number | null;
}

export interface Summary {
  kind: "grant" | "revoke";
  signerVersion: string;
  website: string | null;
  officialWebsite: boolean;
  chainId: number;
  rpcUrl: string;
  development: boolean;
  owner: string;
  transaction: string;
  balance: string;
  grant: {
    delegates: boolean;
    delegate: string;
    codeHashVerified: boolean;
    sessionKey: string;
    botScript: string | null;
    botId: string;
    grantId: string;
    validAfter: number;
    validUntil: number;
    remainingCalls: number;
    rules: RuleSummary[];
    customized: string[];
  } | null;
  revoke: {
    method: string;
    grantId: string;
    grantKind: "policy" | "session";
    delegation: string;
    redelegates: boolean;
    delegate: string;
    delegateName: string;
  } | null;
}

export interface AppInfo {
  version: string;
  os: "windows" | "macos" | "linux" | "android" | "ios";
  arch: string;
  mobile: boolean;
  chainId: number;
  rpc: string;
  defaultApi: string;
  development: boolean;
  /** Started with --selftest: run the packaging self-test and report. */
  selftest: boolean;
  /** Started only to answer an install check (close when done on desktop). */
  launchedForPing: boolean;
}

export interface LinkView {
  action: "sign" | "revoke" | "ping" | "grants";
  api: string;
  official: boolean;
}

export type KeySource =
  | { kind: "keystore"; path?: string; json?: string; password: string }
  | { kind: "privateKey"; secret: string }
  | { kind: "mnemonic"; phrase: string; index: number };

export interface KeyView {
  address: string;
  source: "keystore" | "privateKey" | "mnemonic";
  derivationPath: string | null;
}

export interface SessionView {
  kind: "grant" | "revoke";
  confirmWord: string;
  /** English text (as the command line prints it). */
  summary: string;
  /** The same summary as data: rendered in the selected language. */
  summaryData: Summary;
  editor: EditorPlan | null;
}

export interface SignResult {
  txHash: string;
  block: number;
  reported: boolean;
  reportMessage: string;
}

export interface GrantRow {
  grantId: string;
  kind: string;
  status: string;
  key: string;
  keyOrigin: string;
  bot: string;
  /** "none", "unknown", "deleted", "running" or "stopped". */
  botState: string;
  botScript: string;
  botId: string;
  validUntil: number | null;
  remainingCalls: number | null;
  revocable: boolean;
  active: boolean;
  /** "helix", "none" or "other": the account's code when it was read. */
  delegation: string;
  /** "otherDelegation" when a stored grant cannot be revoked here, else "". */
  notRevocableReason: string;
}

export interface Listing {
  owner: string;
  rows: GrantRow[];
  scanComplete: boolean;
  scanPercent: number;
  truncated: boolean;
}

export interface Pending {
  count: number;
  summaries: string[];
  summaryData: Summary[];
}

export interface RevokeOutcome {
  done: number;
  total: number;
  cancelled: boolean;
  listing: Listing;
  lines: Msg[];
}

export interface SetupView {
  os: AppInfo["os"];
  mobile: boolean;
  handler: string | null;
  command: string | null;
  canRegister: boolean;
  canInstallCli: boolean;
  cliPlaces: string[];
  firstRun: boolean;
}

export interface PingView {
  version: string;
  os: string;
  arch: string;
  api: string;
}

/** A refusal or error from a command. */
export interface CommandError {
  kind: "refused" | "error" | "customize" | "busy" | "cancelled" | "nokey";
  /** English text. */
  message: string;
  /** What the page shows (translated by its code). */
  msg?: Msg;
}

export interface LogEvent {
  scope: "request" | "grants";
  line: string;
  msg?: Msg;
}

/** A message without a code of its own (shown as a headline of its kind and the text). */
export function plainMsg(code: string, text: string): Msg {
  return { code, params: {}, text };
}

/** The message of a command error (older shapes carry only the text). */
export function errorMsg(error: CommandError): Msg {
  return error.msg ?? plainMsg(error.kind === "error" ? "io" : "plan", error.message);
}

export interface Transport {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  listen<T>(event: string, handler: (payload: T) => void): Promise<() => void>;
}

let transport: Transport | null = null;

/** Use another transport (tests, browser preview). */
export function setTransport(value: Transport | null): void {
  transport = value;
}

async function tauriTransport(): Promise<Transport> {
  const [{ invoke }, { listen }] = await Promise.all([import("@tauri-apps/api/core"), import("@tauri-apps/api/event")]);
  return {
    invoke: (command, args) => invoke(command, args),
    listen: async (event, handler) => listen(event, (message) => handler(message.payload as never)),
  };
}

async function current(): Promise<Transport> {
  if (!transport) transport = await tauriTransport();
  return transport;
}

/** Normalise anything a command threw into a CommandError. */
export function asError(error: unknown): CommandError {
  if (error && typeof error === "object" && "kind" in error && "message" in error) return error as CommandError;
  const message = error instanceof Error ? error.message : String(error);
  return { kind: "error", message, msg: plainMsg("io", message) };
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await (await current()).invoke<T>(command, args);
  } catch (error) {
    throw asError(error);
  }
}

export async function on<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
  return (await current()).listen<T>(event, handler);
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),
  initialLink: () => call<string | null>("initial_link"),
  openLink: (url: string) => call<LinkView>("open_link", { url }),
  closeRequest: () => call<void>("close_request"),
  loadKey: (source: KeySource) => call<KeyView>("load_key", { source }),
  keyStatus: () => call<KeyView | null>("key_status"),
  forgetKey: () => call<void>("forget_key"),
  /** The loaded key as an encrypted keystore JSON (the page writes it where the user chose). */
  exportKeystore: (password: string) => call<string>("export_keystore", { password }),
  prepareRequest: () => call<SessionView>("prepare_request"),
  customize: (request: CustomizeRequest | Record<string, never>) => call<SessionView>("customize", { request }),
  sign: (word: string) => call<SignResult>("sign", { word }),
  grantsLoad: () => call<Listing>("grants_load"),
  grantsPrepare: (grantIds: string[] | null) => call<Pending>("grants_prepare", { grantIds }),
  grantsConfirm: (word: string) => call<RevokeOutcome>("grants_confirm", { word }),
  grantsCancel: () => call<void>("grants_cancel"),
  setupStatus: () => call<SetupView>("setup_status"),
  registerLinks: () => call<Msg>("register_links"),
  installCli: () => call<Msg>("install_cli"),
  markFirstRun: () => call<void>("mark_first_run"),
  ping: (url: string) => call<PingView>("ping", { url }),
  touch: () => call<void>("touch"),
  selftestDone: (ok: boolean, detail: string) => call<void>("selftest_done", { ok, detail }),
  /** The window title in the selected language. */
  setTitle: (title: string) => call<void>("set_title", { title }),
  quit: () => call<void>("quit"),
};
