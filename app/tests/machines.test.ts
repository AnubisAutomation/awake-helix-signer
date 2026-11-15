import type { LinkView, Listing, SessionView } from "../src/api";
import { grantSummary, m } from "./fixtures";
import {
  canSign,
  grantsButtons,
  grantsReducer,
  initialGrants,
  initialRequest,
  requestBusy,
  requestReducer,
  shouldPoll,
  wordMatches,
  wouldDiscard,
  type GrantsState,
  type RequestState,
} from "../src/machines";

const link: LinkView = { action: "sign", api: "https://anubis.sivilization.com", official: true };
const session: SessionView = { kind: "grant", confirmWord: "AUTHORIZE", summary: "summary", summaryData: grantSummary(2), editor: { validUntil: 1, remainingCalls: 2, bounds: {}, rules: [] } };
const listing = (rows: Partial<Listing["rows"][number]>[], scanComplete = true): Listing => ({
  owner: "0xowner",
  scanComplete,
  scanPercent: scanComplete ? 100 : 40,
  truncated: false,
  rows: rows.map((row, index) => ({
    grantId: `0x${index}`, kind: "policy", status: "active", key: "0xkey", keyOrigin: "hosted", bot: "bot", botState: "running", botScript: "bot", botId: "1",
    validUntil: 1, remainingCalls: 1, revocable: true, active: true, delegation: "helix", notRevocableReason: "", ...row,
  })),
});

function run(events: Parameters<typeof requestReducer>[1][], start: RequestState = initialRequest): RequestState {
  return events.reduce(requestReducer, start);
}

describe("request machine", () => {
  it("goes open -> verify -> verified -> sign -> done", () => {
    let state = run([{ type: "open", link }]);
    expect(state.phase).toBe("ready");
    state = requestReducer(state, { type: "verify" });
    expect(state.phase).toBe("verifying");
    expect(requestBusy(state)).toBe(true);
    state = requestReducer(state, { type: "verified", session });
    expect(state).toMatchObject({ phase: "verified", message: { key: "request.verified", params: { word: "AUTHORIZE" } } });
    expect(wouldDiscard(state)).toBe(true);
    expect(canSign(state, false)).toBe(true);
    expect(canSign(state, true)).toBe(false);
    state = requestReducer(state, { type: "sign" });
    expect(state.phase).toBe("signing");
    state = requestReducer(state, { type: "signed", result: { txHash: "0xt", block: 5, reported: true, reportMessage: "" } });
    expect(state).toMatchObject({ phase: "done", result: { block: 5 } });
  });

  it("keeps the verified plan when the website refuses an edit", () => {
    const verified = run([{ type: "open", link }, { type: "verify" }, { type: "verified", session }]);
    const applying = requestReducer(verified, { type: "apply" });
    expect(applying.phase).toBe("applying");
    const refused = requestReducer(applying, { type: "editRefused", message: m("plan", "out of range") });
    expect(refused).toMatchObject({ phase: "verified", session, message: { key: "status.refused", tone: "error" } });
    const applied = requestReducer(requestReducer(refused, { type: "apply" }), { type: "applied", session: { ...session, summary: "new" } });
    expect(applied).toMatchObject({ phase: "verified", session: { summary: "new" } });
  });

  it("a refusal ends the request but keeps the link to retry", () => {
    const failed = run([{ type: "open", link }, { type: "verify" }, { type: "failed", message: m("plan", "bad plan") }]);
    expect(failed).toMatchObject({ phase: "ready", link, message: { key: "status.refused", params: { message: m("plan", "bad plan") } } });
    const error = run([{ type: "open", link }, { type: "verify" }, { type: "failed", message: m("plan", "boom"), kind: "error" }]);
    expect(error).toMatchObject({ message: { key: "status.error" } });
  });

  it("ignores events that do not fit the phase", () => {
    expect(run([{ type: "sign" }])).toEqual(initialRequest);
    expect(run([{ type: "verified", session }])).toEqual(initialRequest);
    const ready = run([{ type: "open", link }]);
    expect(requestReducer(ready, { type: "apply" })).toBe(ready);
    expect(requestReducer(ready, { type: "signed", result: { txHash: "", block: 0, reported: false, reportMessage: "" } })).toBe(ready);
  });

  it("does not let a new link or close interrupt a running request", () => {
    const verifying = run([{ type: "open", link }, { type: "verify" }]);
    expect(requestReducer(verifying, { type: "open", link: { ...link, action: "revoke" } })).toBe(verifying);
    expect(requestReducer(verifying, { type: "close" })).toBe(verifying);
    expect(requestReducer(verifying, { type: "refusedLink", message: m("plan", "x") })).toBe(verifying);
  });

  it("opens revoke links, and grants/ping links leave the page empty", () => {
    expect(run([{ type: "open", link: { ...link, action: "revoke" } }]).phase).toBe("ready");
    expect(run([{ type: "open", link: { ...link, action: "grants" } }]).phase).toBe("empty");
    expect(run([{ type: "refusedLink", message: m("plan", "foreign") }])).toMatchObject({ phase: "empty", message: { key: "link.refused" } });
  });

  it("forgetting the key drops a verified plan", () => {
    const verified = run([{ type: "open", link }, { type: "verify" }, { type: "verified", session }]);
    expect(requestReducer(verified, { type: "keyForgotten" }).phase).toBe("ready");
  });

  it("matches the typed word exactly", () => {
    expect(wordMatches(" AUTHORIZE ", "AUTHORIZE")).toBe(true);
    expect(wordMatches("authorize", "AUTHORIZE")).toBe(false);
    expect(wordMatches("AUTHORIZ", "AUTHORIZE")).toBe(false);
  });
});

function grants(events: Parameters<typeof grantsReducer>[1][], start: GrantsState = initialGrants): GrantsState {
  return events.reduce(grantsReducer, start);
}

describe("grants machine", () => {
  const list = listing([{ status: "active" }, { status: "expired", active: false }, { status: "revoked", revocable: false, active: false }]);

  it("offers Revoke only for revocable rows, whatever the status says", () => {
    const rows = listing([
      { status: "inactive", revocable: false, active: false, delegation: "other", notRevocableReason: "otherDelegation" },
      { status: "unavailable", revocable: false, active: false },
      { status: "missing", revocable: false, active: false },
      { status: "a_future_status", revocable: false, active: false },
      { status: "inactive", revocable: true, active: true, delegation: "none" },
    ]);
    let state = grantsReducer(grants([{ type: "load" }]), { type: "listed", listing: rows });
    for (const grantId of ["0x0", "0x1", "0x2", "0x3"]) {
      state = grantsReducer(state, { type: "select", grantId });
      expect(grantsButtons(state).revokeSelected, grantId).toBe(false);
    }
    state = grantsReducer(state, { type: "select", grantId: "0x4" });
    expect(grantsButtons(state)).toMatchObject({ revokeSelected: true, revokeAll: true });
    const none = grantsReducer(grants([{ type: "load" }]), { type: "listed", listing: listing([{ status: "inactive", revocable: false, active: false }]) });
    expect(grantsButtons(none).revokeAll).toBe(false);
  });

  it("loads, selects and revokes one grant", () => {
    let state = grants([{ type: "load" }]);
    expect(state.phase).toBe("loading");
    expect(grantsButtons(state).load).toBe(false);
    state = grantsReducer(state, { type: "listed", listing: list });
    expect(state).toMatchObject({ phase: "listed", message: { key: "grants.count", params: { count: 3 } } });
    expect(grantsButtons(state)).toMatchObject({ load: true, revokeSelected: false, revokeAll: true, confirm: false, cancel: false });
    state = grantsReducer(state, { type: "select", grantId: "0x2" });
    expect(grantsButtons(state).revokeSelected).toBe(false); // already revoked
    state = grantsReducer(state, { type: "select", grantId: "0x1" });
    expect(grantsButtons(state).revokeSelected).toBe(true); // expired but still on chain
    state = grantsReducer(state, { type: "prepare" });
    state = grantsReducer(state, { type: "prepared", pending: { count: 1, summaries: ["s"], summaryData: [] } });
    expect(state.phase).toBe("pending");
    expect(grantsButtons(state)).toMatchObject({ confirm: true, cancel: true, revokeAll: false, load: false });
    state = grantsReducer(state, { type: "confirm" });
    expect(state).toMatchObject({ phase: "revoking", progress: { done: 0, total: 1 } });
    state = grantsReducer(state, { type: "progress", done: 1, total: 1 });
    expect(state.progress).toEqual({ done: 1, total: 1 });
    const after = listing([{ status: "active" }, { status: "revoked", revocable: false, active: false }]);
    state = grantsReducer(state, { type: "finished", outcome: { done: 1, total: 1, cancelled: false, listing: after, lines: [] } });
    expect(state).toMatchObject({ phase: "listed", progress: null, message: { key: "grants.finished", params: { done: 1, total: 1 } } });
    expect(state.selected).toBe("0x1");
  });

  it("revoke all, then cancel while revoking stops after the current one", () => {
    let state = grants([{ type: "load" }, { type: "listed", listing: list }, { type: "prepare" }, { type: "prepared", pending: { count: 2, summaries: [], summaryData: [] } }, { type: "confirm" }]);
    state = grantsReducer(state, { type: "cancel" });
    expect(state).toMatchObject({ phase: "revoking", stopping: true, message: { key: "grants.stopping" } });
    expect(grantsButtons(state).cancel).toBe(false);
    state = grantsReducer(state, { type: "finished", outcome: { done: 1, total: 2, cancelled: true, listing: list, lines: [] } });
    expect(state.message).toMatchObject({ key: "grants.finishedCancelled" });
  });

  it("cancel before signing discards the verified revocations", () => {
    const state = grants([{ type: "load" }, { type: "listed", listing: list }, { type: "prepare" }, { type: "prepared", pending: { count: 1, summaries: [], summaryData: [] } }, { type: "cancel" }]);
    expect(state).toMatchObject({ phase: "listed", pending: null, message: { key: "grants.cancelled" } });
  });

  it("nothing to revoke goes back to the list", () => {
    const state = grants([{ type: "load" }, { type: "listed", listing: list }, { type: "prepare" }, { type: "prepared", pending: { count: 0, summaries: [], summaryData: [] } }]);
    expect(state).toMatchObject({ phase: "listed", message: { key: "grants.nothing" } });
  });

  it("a refusal keeps the list (and the key) for a retry", () => {
    const listed = grants([{ type: "load" }, { type: "listed", listing: list }]);
    expect(grantsReducer(grantsReducer(listed, { type: "load" }), { type: "failed", message: m("plan", "x") })).toMatchObject({ phase: "listed", listing: list });
    expect(grants([{ type: "load" }, { type: "failed", message: m("plan", "login refused") }])).toMatchObject({ phase: "locked", message: { params: { message: m("plan", "login refused") } } });
  });

  it("polls while the website scans and ignores a quiet poll mid-action", () => {
    const scanning = grants([{ type: "load" }, { type: "listed", listing: listing([{}], false) }]);
    expect(shouldPoll(scanning)).toBe(true);
    const preparing = grantsReducer(scanning, { type: "prepare" });
    expect(grantsReducer(preparing, { type: "listed", listing: list, quiet: true })).toBe(preparing);
    expect(shouldPoll(grantsReducer(scanning, { type: "listed", listing: list, quiet: true }))).toBe(false);
  });

  it("selection is frozen while a revocation is pending", () => {
    const pending = grants([{ type: "load" }, { type: "listed", listing: list }, { type: "select", grantId: "0x0" }, { type: "prepare" }, { type: "prepared", pending: { count: 1, summaries: [], summaryData: [] } }]);
    expect(grantsReducer(pending, { type: "select", grantId: "0x1" }).selected).toBe("0x0");
    expect(grantsReducer(pending, { type: "forget" })).toEqual(initialGrants);
  });
});
