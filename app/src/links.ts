// What the user pasted or what the OS delivered: an anubisauto:// link (or a
// legacy awakehelix:// one: old links and QR codes still open the app) or a
// bare plan token. This only routes the input; the backend (the core's link
// parser) decides whether the link and its website are acceptable.

/** The scheme of every link the app makes. */
export const SCHEME = "anubisauto";
/** The scheme of the signers before 0.7.0: accepted, never made. */
export const LEGACY_SCHEME = "awakehelix";
export const SCHEMES = [SCHEME, LEGACY_SCHEME] as const;
const LINK = new RegExp(`^(?:${SCHEMES.join("|")}):(?:\\/\\/)?\\/*([a-z]+)`, "i");
export const ACTIONS = ["sign", "revoke", "ping", "grants"] as const;
export type Action = (typeof ACTIONS)[number];
export const TOKEN = /^[A-Za-z0-9_-]{22,128}$/;

export type Input =
  | { kind: "link"; url: string; action: Action }
  | { kind: "token"; token: string }
  | { kind: "invalid"; reason: "empty" | "scheme" | "action" | "token" };

/** Whether text starts with one of our schemes and a colon (any case). */
export function isOurs(text: string): boolean {
  const lower = text.toLowerCase();
  return SCHEMES.some((scheme) => lower.startsWith(scheme + ":"));
}

/** The action of an anubisauto:// (or awakehelix://) link, without validating its parameters. */
export function actionOf(url: string): Action | null {
  const match = LINK.exec(url.trim());
  if (!match) return null;
  const action = match[1].toLowerCase();
  return (ACTIONS as readonly string[]).includes(action) ? (action as Action) : null;
}

/** Classify pasted text: a link (any action), a bare plan token, or neither. */
export function classify(text: string): Input {
  const value = text.trim();
  if (!value) return { kind: "invalid", reason: "empty" };
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    if (!isOurs(value)) return { kind: "invalid", reason: "scheme" };
    const action = actionOf(value);
    return action ? { kind: "link", url: value, action } : { kind: "invalid", reason: "action" };
  }
  return TOKEN.test(value) ? { kind: "token", token: value } : { kind: "invalid", reason: "token" };
}

/** The first of our URLs among several (deep-link events may carry a list). */
export function firstLink(urls: readonly string[] | null | undefined): string | null {
  return (urls ?? []).find((url) => isOurs(url)) ?? null;
}

/** A sign link for a pasted token (the official website unless `api` is given). */
export function tokenLink(token: string, api?: string): string {
  const query = new URLSearchParams({ plan: token });
  if (api) query.set("api", api);
  return `${SCHEME}://sign?${query.toString()}`;
}

/** Short form of a hex value: 0x1234…abcd. */
export function short(hex: string, head = 6, tail = 4): string {
  if (!hex) return "-";
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
