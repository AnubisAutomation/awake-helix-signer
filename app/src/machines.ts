// The two working pages as small state machines: what may happen next is
// decided here (pure functions, unit-tested), the views only render a state
// and send events.
import type { LinkView, Listing, Msg, Pending, RevokeOutcome, SessionView, SignResult } from "./api";

// ---------------------------------------------------------------- request

export type RequestState =
  | { phase: "empty"; message?: Note }
  | { phase: "ready"; link: LinkView; message?: Note }
  | { phase: "verifying"; link: LinkView }
  | { phase: "verified"; link: LinkView; session: SessionView; message?: Note }
  | { phase: "applying"; link: LinkView; session: SessionView }
  | { phase: "signing"; link: LinkView; session: SessionView }
  | { phase: "done"; link: LinkView; result: SignResult };

/** A status line: a message key with parameters (a parameter may be a
 * backend message, translated on its own); key "%msg" shows `params.msg`. */
export type Note = { key: string; params?: Record<string, string | number | Msg>; tone?: "info" | "error" | "ok" };

export type RequestEvent =
  | { type: "open"; link: LinkView }
  | { type: "refusedLink"; message: Msg }
  | { type: "close" }
  | { type: "verify" }
  | { type: "verified"; session: SessionView }
  | { type: "apply" }
  | { type: "applied"; session: SessionView }
  | { type: "editRefused"; message: Msg }
  | { type: "sign" }
  | { type: "signed"; result: SignResult }
  | { type: "failed"; message: Msg; kind?: string }
  | { type: "keyForgotten" };

export const initialRequest: RequestState = { phase: "empty" };

/** Whether a request is in flight (a new link must wait). */
export function requestBusy(state: RequestState): boolean {
  return state.phase === "verifying" || state.phase === "applying" || state.phase === "signing";
}

/** Whether opening another link would discard a verified, unsigned plan. */
export function wouldDiscard(state: RequestState): boolean {
  return state.phase === "verified";
}

const refusal = (message: Msg, kind?: string): Note => ({
  key: kind === "error" ? "status.error" : "status.refused",
  params: { message },
  tone: "error",
});

export function requestReducer(state: RequestState, event: RequestEvent): RequestState {
  switch (event.type) {
    case "open":
      if (requestBusy(state)) return state;
      if (event.link.action === "sign" || event.link.action === "revoke") {
        return { phase: "ready", link: event.link, message: { key: "request.chooseKey" } };
      }
      return { phase: "empty" };
    case "refusedLink":
      if (requestBusy(state)) return state;
      return { phase: "empty", message: { key: "link.refused", params: { message: event.message }, tone: "error" } };
    case "close":
      return requestBusy(state) ? state : { phase: "empty" };
    case "verify":
      return state.phase === "ready" || state.phase === "done" ? { phase: "verifying", link: state.link } : state;
    case "verified":
    case "applied":
      if (state.phase !== "verifying" && state.phase !== "applying") return state;
      return {
        phase: "verified",
        link: state.link,
        session: event.session,
        message: { key: "request.verified", params: { word: event.session.confirmWord } },
      };
    case "apply":
      return state.phase === "verified" && state.session.editor ? { phase: "applying", link: state.link, session: state.session } : state;
    case "editRefused":
      // The website refused the edited values: keep the plan shown, fix the fields.
      if (state.phase !== "applying") return state;
      return { phase: "verified", link: state.link, session: state.session, message: refusal(event.message) };
    case "sign":
      return state.phase === "verified" ? { phase: "signing", link: state.link, session: state.session } : state;
    case "signed":
      return state.phase === "signing" ? { phase: "done", link: state.link, result: event.result } : state;
    case "failed":
      // A refusal ends the request (the backend wiped the key); the link stays to retry.
      if (state.phase === "empty") return { phase: "empty", message: refusal(event.message, event.kind) };
      return { phase: "ready", link: state.link, message: refusal(event.message, event.kind) };
    case "keyForgotten":
      if (state.phase === "verified") return { phase: "ready", link: state.link, message: { key: "request.chooseKey" } };
      return state;
  }
}

/** Whether the Sign button may be pressed. */
export function canSign(state: RequestState, editorDirty: boolean): boolean {
  return state.phase === "verified" && !editorDirty;
}

/** Whether the typed word matches exactly (surrounding spaces are ignored, case is not). */
/**
 * The typed confirmation word, made comparable: full-width letters from an
 * input method (ＡＵＴＨＯＲＩＺＥ) become ASCII (NFKC), spaces and invisible
 * characters are dropped, and case is ignored.
 */
export function normalizeWord(typed: string): string {
  return typed.normalize("NFKC").replace(/[\s\u200B-\u200D\u2060\uFEFF]/gu, "").toUpperCase();
}

/** Whether the typed text is the confirmation word (see `normalizeWord`). */
export function wordMatches(typed: string, word: string): boolean {
  return normalizeWord(typed) === word.toUpperCase();
}

/** An Enter that only commits an input method's composition (e.g. Zhuyin) must not submit. */
export function isComposingEnter(event: KeyboardEvent): boolean {
  return event.key === "Enter" && (event.isComposing || event.keyCode === 229);
}

// ----------------------------------------------------------------- grants

export type GrantsState = {
  phase: "locked" | "loading" | "listed" | "preparing" | "pending" | "revoking";
  listing: Listing | null;
  selected: string | null;
  pending: Pending | null;
  progress: { done: number; total: number } | null;
  stopping: boolean;
  message?: Note;
};

export type GrantsEvent =
  | { type: "load" }
  | { type: "listed"; listing: Listing; quiet?: boolean }
  | { type: "failed"; message: Msg; kind?: string }
  | { type: "select"; grantId: string | null }
  | { type: "prepare" }
  | { type: "prepared"; pending: Pending }
  | { type: "confirm" }
  | { type: "progress"; done: number; total: number }
  | { type: "finished"; outcome: RevokeOutcome }
  | { type: "cancel" }
  | { type: "forget" };

export const initialGrants: GrantsState = {
  phase: "locked",
  listing: null,
  selected: null,
  pending: null,
  progress: null,
  stopping: false,
};

export function grantsBusy(state: GrantsState): boolean {
  return state.phase === "loading" || state.phase === "preparing" || state.phase === "revoking";
}

export function selectedRow(state: GrantsState) {
  return state.listing?.rows.find((row) => row.grantId === state.selected) ?? null;
}

/** Buttons the current state allows. */
export function grantsButtons(state: GrantsState) {
  const idle = !grantsBusy(state);
  const listed = state.phase === "listed";
  const row = selectedRow(state);
  return {
    load: idle && state.phase !== "pending",
    revokeSelected: listed && !!row && row.revocable,
    revokeAll: listed && (state.listing?.rows.some((item) => item.active) ?? false),
    confirm: state.phase === "pending",
    cancel: state.phase === "pending" || (state.phase === "revoking" && !state.stopping),
  };
}

export function grantsReducer(state: GrantsState, event: GrantsEvent): GrantsState {
  switch (event.type) {
    case "load":
      return grantsBusy(state) ? state : { ...state, phase: "loading", pending: null, message: { key: "status.working" } };
    case "listed": {
      if (event.quiet && state.phase !== "listed") return state;
      const selected = event.listing.rows.some((row) => row.grantId === state.selected) ? state.selected : null;
      return {
        ...state,
        phase: "listed",
        listing: event.listing,
        selected,
        pending: null,
        progress: null,
        stopping: false,
        message: event.quiet ? state.message : { key: "grants.count", params: { count: event.listing.rows.length, owner: event.listing.owner } },
      };
    }
    case "failed":
      return {
        ...state,
        phase: state.listing ? "listed" : "locked",
        pending: null,
        progress: null,
        stopping: false,
        message: refusal(event.message, event.kind),
      };
    case "select":
      return grantsBusy(state) || state.phase === "pending" ? state : { ...state, selected: event.grantId };
    case "prepare":
      return state.phase === "listed" ? { ...state, phase: "preparing", message: { key: "status.working" } } : state;
    case "prepared":
      if (state.phase !== "preparing") return state;
      if (event.pending.count === 0) return { ...state, phase: "listed", pending: null, message: { key: "grants.nothing" } };
      return { ...state, phase: "pending", pending: event.pending, message: { key: "grants.confirmPrompt", params: { count: event.pending.count } } };
    case "confirm":
      return state.phase === "pending" && state.pending
        ? { ...state, phase: "revoking", progress: { done: 0, total: state.pending.count }, message: { key: "grants.revoking", params: { number: 1, total: state.pending.count } } }
        : state;
    case "progress":
      if (state.phase !== "revoking") return state;
      return {
        ...state,
        progress: { done: event.done, total: event.total },
        message: state.stopping
          ? state.message
          : { key: "grants.revoking", params: { number: Math.min(event.done + 1, event.total), total: event.total } },
      };
    case "finished": {
      const { done, total, listing } = event.outcome;
      return {
        ...state,
        phase: "listed",
        listing,
        pending: null,
        progress: null,
        stopping: false,
        selected: listing.rows.some((row) => row.grantId === state.selected) ? state.selected : null,
        message: { key: done < total ? "grants.finishedCancelled" : "grants.finished", params: { done, total }, tone: "ok" },
      };
    }
    case "cancel":
      if (state.phase === "pending") return { ...state, phase: "listed", pending: null, message: { key: "grants.cancelled" } };
      if (state.phase === "revoking") return { ...state, stopping: true, message: { key: "grants.stopping" } };
      return state;
    case "forget":
      return { ...initialGrants };
  }
}

/** Whether the list should be read again soon (the website still scans the install history). */
export function shouldPoll(state: GrantsState): boolean {
  return state.phase === "listed" && !!state.listing && !state.listing.scanComplete;
}

/** Reads of the list while the website answers from its cached copy. */
export const REFRESH_POLLS = 5;

/** Why the list should be read again soon: the website scans the install
 * history, or it sent its cached copy while it refreshes the statuses from
 * the chain (`refreshes`: reads already made for that, at most
 * `REFRESH_POLLS`); null when not. */
export function pollReason(state: GrantsState, refreshes: number): "scan" | "refresh" | null {
  if (shouldPoll(state)) return "scan";
  if (state.phase === "listed" && state.listing?.refreshing && refreshes < REFRESH_POLLS) return "refresh";
  return null;
}
