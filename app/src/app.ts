// The app's state and actions. Views render `store` and call these actions;
// every decision about what is safe to sign happens in the backend and the
// core library, this only sequences the commands and shows their results.
import { api, errorMsg, on, plainMsg, type AppInfo, type CommandError, type KeySource, type KeyView, type LinkView, type LogEvent, type Msg, type PingView, type SessionView, type SetupView } from "./api";
import { buildRequest, EditError, fieldsOf, isDirty, LOCAL, type CustomizeRequest, type Fields } from "./editor";
import { classify, firstLink, tokenLink } from "./links";
import {
  grantsBusy,
  grantsReducer,
  initialGrants,
  initialRequest,
  requestBusy,
  requestReducer,
  shouldPoll,
  wordMatches,
  wouldDiscard,
  type GrantsEvent,
  type GrantsState,
  type Note,
  type RequestEvent,
  type RequestState,
} from "./machines";
import { confirmDialog } from "./dom";
import { en } from "./i18n/en";
import { onLanguage, t } from "./i18n";
import { msgNote, type LogEntry } from "./views/common";

export type Tab = "request" | "grants" | "computer";
export type KeyKind = KeySource["kind"];

export interface KeyForm {
  source: KeyKind;
  /** Desktop keystore path. */
  path: string;
  /** Mobile keystore text (encrypted JSON). */
  json: string;
  fileName: string;
  index: string;
}

export interface PingState {
  phase: "sending" | "linked" | "failed";
  api: string;
  result?: PingView;
  message?: Msg;
  countdown?: number;
}

export interface Store {
  info: AppInfo | null;
  tab: Tab;
  link: LinkView | null;
  key: KeyView | null;
  keyBusy: boolean;
  keyForm: KeyForm;
  request: RequestState;
  grants: GrantsState;
  editor: { fields: Fields | null; zone: string; error: Note | null; refused: CustomizeRequest | null };
  logs: { request: LogEntry[]; grants: LogEntry[] };
  status: Note | null;
  setup: SetupView | null;
  ping: PingState | null;
}

export const SCAN_POLL_MS = 5000;
export const PING_CLOSE_SECONDS = 5;

export const store: Store = {
  info: null,
  tab: "request",
  link: null,
  key: null,
  keyBusy: false,
  keyForm: { source: "keystore", path: "", json: "", fileName: "", index: "0" },
  request: initialRequest,
  grants: initialGrants,
  editor: { fields: null, zone: LOCAL, error: null, refused: null },
  logs: { request: [], grants: [] },
  status: null,
  setup: null,
  ping: null,
};

type Listener = () => void;
const listeners = new Set<Listener>();
export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
export function changed(): void {
  listeners.forEach((listener) => listener());
}

/** Secret inputs are read from the DOM at use and cleared at once; they never enter `store`. */
export interface SecretInputs {
  read(): { password: string; privateKey: string; mnemonic: string };
  clear(): void;
}
let secrets: SecretInputs = { read: () => ({ password: "", privateKey: "", mnemonic: "" }), clear: () => {} };
export function useSecrets(value: SecretInputs): void {
  secrets = value;
}

function note(key: string, params?: Note["params"], tone?: Note["tone"]): Note {
  return { key, params, tone };
}

function errorNote(error: CommandError): Note {
  return note(error.kind === "error" ? "status.error" : "status.refused", { message: errorMsg(error) }, "error");
}

/** A refusal found here (not by the backend), shown with one of the page's own texts. */
export function uiError(key: keyof typeof en): CommandError {
  return { kind: "nokey", message: en[key], msg: { code: `ui:${key}`, params: {}, text: en[key] } };
}

function dispatchRequest(event: RequestEvent): void {
  store.request = requestReducer(store.request, event);
  if ("message" in store.request && store.request.message) store.status = store.request.message;
  changed();
}

function dispatchGrants(event: GrantsEvent): void {
  store.grants = grantsReducer(store.grants, event);
  if (store.grants.message) store.status = store.grants.message;
  changed();
}

export function setTab(tab: Tab): void {
  store.tab = tab;
  if (tab === "computer") void refreshSetup();
  changed();
}

export function log(scope: "request" | "grants", entry: LogEntry): void {
  store.logs[scope] = [...store.logs[scope], entry].slice(-500);
  changed();
}

// ------------------------------------------------------------------ links

/** Handle a link from the OS (deep link, second instance) or the paste box. */
export async function handleUrl(url: string): Promise<void> {
  const input = classify(url);
  if (input.kind === "invalid") {
    store.status = note(`link.invalid.${input.reason}`, {}, "error");
    changed();
    return;
  }
  const target = input.kind === "token" ? tokenLink(input.token) : input.url;
  const action = input.kind === "token" ? "sign" : input.action;
  if (action === "ping") {
    await runPing(target);
    return;
  }
  if (action !== "grants") {
    if (requestBusy(store.request) || grantsBusy(store.grants)) {
      store.status = note("request.busy", {}, "error");
      changed();
      return;
    }
    if (wouldDiscard(store.request) && !(await confirmDialog(() => t("request.discard"), () => t("common.yes"), () => t("common.no")))) return;
  }
  try {
    const link = await api.openLink(target);
    store.link = link;
    if (link.action === "grants") {
      store.tab = "grants";
      store.status = note("grants.help");
      changed();
      return;
    }
    store.logs.request = [];
    resetEditor();
    store.tab = "request";
    dispatchRequest({ type: "open", link });
  } catch (error) {
    store.tab = "request";
    dispatchRequest({ type: "refusedLink", message: errorMsg(error as CommandError) });
  }
}

export async function closeRequest(): Promise<void> {
  if (requestBusy(store.request)) return;
  await api.closeRequest().catch(() => undefined);
  resetEditor();
  dispatchRequest({ type: "close" });
}

// -------------------------------------------------------------------- key

export function keySource(): KeySource {
  const form = store.keyForm;
  const typed = secrets.read();
  if (form.source === "keystore") {
    if (!form.path && !form.json) throw uiError("key.needFile");
    return form.path
      ? { kind: "keystore", path: form.path, password: typed.password }
      : { kind: "keystore", json: form.json, password: typed.password };
  }
  if (form.source === "privateKey") {
    if (!typed.privateKey.trim()) throw uiError("key.needSecret");
    return { kind: "privateKey", secret: typed.privateKey };
  }
  if (!typed.mnemonic.trim()) throw uiError("key.needSecret");
  if (!/^\d{1,6}$/.test(form.index.trim() || "0")) throw uiError("key.badIndex");
  return { kind: "mnemonic", phrase: typed.mnemonic, index: Number(form.index.trim() || "0") };
}

/** The loaded key, unlocking it from the form when needed. */
async function ensureKey(scope: "request" | "grants"): Promise<KeyView> {
  if (store.key) return store.key;
  // The secret is read once and leaves the page at once.
  const source = keySource();
  secrets.clear();
  store.keyBusy = true;
  changed();
  try {
    const key = await api.loadKey(source);
    store.key = key;
    log(scope, note("key.loaded", { address: key.address }));
    return key;
  } finally {
    store.keyBusy = false;
    changed();
  }
}

export async function syncKey(): Promise<void> {
  store.key = await api.keyStatus().catch(() => null);
  if (!store.key) {
    store.grants = grantsReducer(store.grants, { type: "forget" });
    store.request = requestReducer(store.request, { type: "keyForgotten" });
  }
  changed();
}

export async function forgetKey(): Promise<void> {
  await api.forgetKey().catch(() => undefined);
  store.key = null;
  secrets.clear();
  stopPolling();
  store.grants = grantsReducer(store.grants, { type: "forget" });
  store.request = requestReducer(store.request, { type: "keyForgotten" });
  if (store.request.phase === "ready") resetEditor();
  store.status = note("key.forgotten");
  changed();
}

export function keyWiped(): void {
  store.key = null;
  stopPolling();
  store.grants = grantsReducer(store.grants, { type: "forget" });
  store.request = requestReducer(store.request, { type: "keyForgotten" });
  store.status = note("key.wiped");
  changed();
}

// ---------------------------------------------------------------- request

function resetEditor(): void {
  store.editor = { fields: null, zone: store.editor.zone, error: null, refused: null };
}

/** Load the editor fields of a verified session (before it is rendered). */
function showSession(session: SessionView): void {
  store.editor.fields = session.editor ? fieldsOf(session.editor, store.editor.zone) : null;
  store.editor.error = null;
}

export async function verify(): Promise<void> {
  const state = store.request;
  if (state.phase !== "ready" && state.phase !== "done") return;
  dispatchRequest({ type: "verify" });
  store.status = note("status.working");
  changed();
  try {
    await ensureKey("request");
    const session = await api.prepareRequest();
    store.editor.refused = null;
    showSession(session);
    dispatchRequest({ type: "verified", session });
    log("request", { summary: session.summaryData });
    changed();
  } catch (error) {
    await requestFailed(error as CommandError);
  }
}

async function requestFailed(error: CommandError): Promise<void> {
  resetEditor();
  dispatchRequest({ type: "failed", message: errorMsg(error), kind: error.kind });
  log("request", errorNote(error));
  await syncKey();
}

export function editorChanged(fields: Fields): void {
  store.editor.fields = fields;
  store.editor.error = null;
}

export function editorDirty(): boolean {
  const state = store.request;
  if (state.phase !== "verified" || !state.session.editor || !store.editor.fields) return false;
  return isDirty(state.session.editor, store.editor.fields);
}

/** Send the edited values to the website (via the backend) and verify the new plan. */
export async function applyEdit(): Promise<void> {
  const state = store.request;
  if (state.phase !== "verified" || !state.session.editor || !store.editor.fields || !editorDirty()) return;
  let request: CustomizeRequest;
  try {
    request = buildRequest(state.session.editor, store.editor.fields);
  } catch (error) {
    if (error instanceof EditError) {
      store.editor.error = note(error.key, error.params, "error");
      changed();
      return;
    }
    throw error;
  }
  if (store.editor.refused && JSON.stringify(store.editor.refused) === JSON.stringify(request)) return;
  await customize(request);
}

export async function editorDefaults(): Promise<void> {
  if (store.request.phase !== "verified" || !store.request.session.editor) return;
  await customize({});
}

async function customize(request: CustomizeRequest | Record<string, never>): Promise<void> {
  dispatchRequest({ type: "apply" });
  store.status = note("editor.applying");
  changed();
  try {
    const session = await api.customize(request);
    store.editor.refused = null;
    showSession(session);
    dispatchRequest({ type: "applied", session });
    log("request", { summary: session.summaryData });
    changed();
  } catch (error) {
    const problem = error as CommandError;
    if (problem.kind === "customize") {
      store.editor.refused = "validUntil" in request ? (request as CustomizeRequest) : null;
      dispatchRequest({ type: "editRefused", message: errorMsg(problem) });
      store.editor.error = note("status.refused", { message: errorMsg(problem) }, "error");
      changed();
      return;
    }
    await requestFailed(problem);
  }
}

export async function sign(word: string): Promise<boolean> {
  const state = store.request;
  if (state.phase !== "verified" || editorDirty()) return false;
  if (!wordMatches(word, state.session.confirmWord)) {
    store.status = note("sign.mustType", { word: state.session.confirmWord }, "error");
    changed();
    return false;
  }
  dispatchRequest({ type: "sign" });
  store.status = note("sign.signing");
  changed();
  try {
    const result = await api.sign(word.trim());
    dispatchRequest({ type: "signed", result });
    resetEditor();
    log("request", note("result.done", { tx: result.txHash, block: result.block }, "ok"));
    log("request", note(result.reported ? "result.reported" : "result.onChain"));
    store.status = { key: "result.done", params: { tx: result.txHash, block: result.block }, tone: "ok" };
    await syncKey();
    return true;
  } catch (error) {
    await requestFailed(error as CommandError);
    return false;
  }
}

// ----------------------------------------------------------------- grants

let pollTimer: ReturnType<typeof setTimeout> | null = null;

function stopPolling(): void {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

function schedulePoll(): void {
  stopPolling();
  if (!shouldPoll(store.grants)) return;
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    if (!shouldPoll(store.grants)) return;
    try {
      dispatchGrants({ type: "listed", listing: await api.grantsLoad(), quiet: true });
      schedulePoll();
    } catch (error) {
      log("grants", errorNote(error as CommandError));
    }
  }, SCAN_POLL_MS);
}

export async function loadGrants(): Promise<void> {
  if (grantsBusy(store.grants)) return;
  dispatchGrants({ type: "load" });
  try {
    await ensureKey("grants");
    dispatchGrants({ type: "listed", listing: await api.grantsLoad() });
    schedulePoll();
  } catch (error) {
    grantsFailed(error as CommandError);
    await syncKey();
  }
}

function grantsFailed(error: CommandError): void {
  log("grants", errorNote(error));
  dispatchGrants({ type: "failed", message: errorMsg(error), kind: error.kind });
}

export function selectGrant(grantId: string | null): void {
  dispatchGrants({ type: "select", grantId });
}

export async function prepareRevoke(all: boolean): Promise<void> {
  const state = store.grants;
  const ids = all ? null : state.selected ? [state.selected] : [];
  if (ids && !ids.length) return;
  stopPolling();
  dispatchGrants({ type: "prepare" });
  try {
    const pending = await api.grantsPrepare(ids);
    pending.summaryData.forEach((summary) => log("grants", { summary }));
    dispatchGrants({ type: "prepared", pending });
    if (pending.count === 0) await loadGrants();
  } catch (error) {
    grantsFailed(error as CommandError);
  }
}

export async function confirmRevoke(word: string): Promise<boolean> {
  if (store.grants.phase !== "pending") return false;
  if (!wordMatches(word, "REVOKE")) {
    store.status = note("grants.mustType", {}, "error");
    changed();
    return false;
  }
  dispatchGrants({ type: "confirm" });
  try {
    const outcome = await api.grantsConfirm(word.trim());
    outcome.lines.forEach((line) => log("grants", msgNote(line)));
    dispatchGrants({ type: "finished", outcome });
    log("grants", note(outcome.done < outcome.total ? "grants.finishedCancelled" : "grants.finished", { done: outcome.done, total: outcome.total }));
    schedulePoll();
    return true;
  } catch (error) {
    grantsFailed(error as CommandError);
    return false;
  }
}

export function grantsProgress(done: number, total: number): void {
  dispatchGrants({ type: "progress", done, total });
}

export async function cancelRevoke(): Promise<void> {
  const phase = store.grants.phase;
  if (phase !== "pending" && phase !== "revoking") return;
  await api.grantsCancel().catch(() => undefined);
  if (phase === "pending") log("grants", note("grants.cancelled"));
  dispatchGrants({ type: "cancel" });
}

// --------------------------------------------------------------- computer

export async function refreshSetup(): Promise<void> {
  try {
    store.setup = await api.setupStatus();
  } catch {
    store.setup = null;
  }
  changed();
}

export async function registerLinks(): Promise<void> {
  try {
    store.status = msgNote(await api.registerLinks(), "ok");
  } catch (error) {
    store.status = errorNote(error as CommandError);
  }
  await refreshSetup();
}

export async function installCli(): Promise<void> {
  const places = store.setup?.cliPlaces.join(" / ") ?? "~/.local/bin";
  if (!(await confirmDialog(() => t("computer.installCliConfirm", { places }), () => t("common.yes"), () => t("common.no")))) return;
  try {
    store.status = msgNote(await api.installCli(), "ok");
  } catch (error) {
    store.status = errorNote(error as CommandError);
  }
  await refreshSetup();
}

/** AppImage first run: offer to register links and the command once. */
export async function firstRun(): Promise<void> {
  await refreshSetup();
  if (!store.setup?.firstRun) return;
  await api.markFirstRun().catch(() => undefined);
  if (!(await confirmDialog(() => t("computer.firstRun"), () => t("common.yes"), () => t("common.no")))) return;
  await registerLinks();
  if (store.setup?.canInstallCli) {
    try {
      store.status = msgNote(await api.installCli(), "ok");
    } catch (error) {
      store.status = errorNote(error as CommandError);
    }
    await refreshSetup();
  }
}

// ------------------------------------------------------------------- ping

export async function runPing(url: string): Promise<void> {
  const shown: PingState = { phase: "sending", api: "" };
  store.ping = shown;
  changed();
  try {
    const result = await api.ping(url);
    store.ping = { phase: "linked", api: result.api, result };
    changed();
    if (store.info?.launchedForPing && !store.info.mobile) countdown();
  } catch (error) {
    store.ping = { phase: "failed", api: "", message: errorMsg(error as CommandError) };
    changed();
  }
}

function countdown(): void {
  let remaining = PING_CLOSE_SECONDS;
  const tick = () => {
    if (!store.ping) return;
    if (remaining <= 0) {
      void api.quit();
      return;
    }
    store.ping = { ...store.ping, countdown: remaining };
    remaining -= 1;
    changed();
    setTimeout(tick, 1000);
  };
  tick();
}

export function closePing(): void {
  const launched = store.info?.launchedForPing && !store.info.mobile && store.ping?.phase === "linked";
  store.ping = null;
  changed();
  if (launched) void api.quit();
}

// ------------------------------------------------------------------- boot

let titleFollows = false;

/** The window title follows the selected language. */
function syncTitle(): void {
  if (store.info) void api.setTitle(`${t("app.title")} ${store.info.version}`).catch(() => undefined);
}

export async function start(): Promise<void> {
  store.info = await api.appInfo();
  syncTitle();
  if (!titleFollows) onLanguage(syncTitle);
  titleFollows = true;
  document.documentElement.dataset.os = store.info.os;
  await on<string>("signer://link", (url) => void handleUrl(url));
  await on<LogEvent>("signer://log", (event) => log(event.scope, msgNote(event.msg ?? plainMsg("log", event.line))));
  await on<{ done: number; total: number }>("signer://progress", (event) => grantsProgress(event.done, event.total));
  await on<null>("signer://key-wiped", () => keyWiped());
  await on<string[]>("deep-link://new-url", (urls) => {
    const url = firstLink(urls);
    if (url) void handleUrl(url);
  });
  const initial = await api.initialLink().catch(() => null);
  if (initial) await handleUrl(initial);
  else {
    store.tab = "grants";
    store.status = note("grants.help");
  }
  changed();
  if (!store.info.mobile && !store.info.selftest && !store.info.launchedForPing) void firstRun();
}
