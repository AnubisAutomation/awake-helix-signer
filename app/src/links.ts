// What the user pasted or what the OS delivered: an awakehelix:// link or a
// bare plan token. This only routes the input; the backend (the core's link
// parser) decides whether the link and its website are acceptable.

export const SCHEME = "awakehelix";
export const ACTIONS = ["sign", "revoke", "ping", "grants"] as const;
export type Action = (typeof ACTIONS)[number];
export const TOKEN = /^[A-Za-z0-9_-]{22,128}$/;

export type Input =
  | { kind: "link"; url: string; action: Action }
  | { kind: "token"; token: string }
  | { kind: "invalid"; reason: "empty" | "scheme" | "action" | "token" };

/** The action of an awakehelix:// link, without validating its parameters. */
export function actionOf(url: string): Action | null {
  const match = /^awakehelix:(?:\/\/)?\/*([a-z]+)/i.exec(url.trim());
  if (!match) return null;
  const action = match[1].toLowerCase();
  return (ACTIONS as readonly string[]).includes(action) ? (action as Action) : null;
}

/** Classify pasted text: a link (any action), a bare plan token, or neither. */
export function classify(text: string): Input {
  const value = text.trim();
  if (!value) return { kind: "invalid", reason: "empty" };
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    if (!value.toLowerCase().startsWith(SCHEME + ":")) return { kind: "invalid", reason: "scheme" };
    const action = actionOf(value);
    return action ? { kind: "link", url: value, action } : { kind: "invalid", reason: "action" };
  }
  return TOKEN.test(value) ? { kind: "token", token: value } : { kind: "invalid", reason: "token" };
}

/** The first awakehelix:// URL among several (deep-link events may carry a list). */
export function firstLink(urls: readonly string[] | null | undefined): string | null {
  return (urls ?? []).find((url) => url.toLowerCase().startsWith(SCHEME + ":")) ?? null;
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
