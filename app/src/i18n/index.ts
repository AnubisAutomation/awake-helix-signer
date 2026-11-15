// Six languages; the default follows the OS/browser language, the switcher's
// choice is remembered on this device (a UI preference, never a secret).
import type { Msg, SiteText } from "../api";
import { en, type Dictionary, type Key } from "./en";
import { es } from "./es";
import { ja } from "./ja";
import { ko } from "./ko";
import { zhHans } from "./zh-Hans";
import { zhHant } from "./zh-Hant";

export type { Key } from "./en";
export const LANGUAGES = ["zh-Hant", "zh-Hans", "en", "ja", "ko", "es"] as const;
export type Language = (typeof LANGUAGES)[number];
export const NAMES: Record<Language, string> = {
  "zh-Hant": "繁體中文",
  "zh-Hans": "简体中文",
  en: "English",
  ja: "日本語",
  ko: "한국어",
  es: "Español",
};
export const DICTIONARIES: Record<Language, Dictionary> = {
  "zh-Hant": zhHant,
  "zh-Hans": zhHans,
  en,
  ja,
  ko,
  es,
};
const STORAGE = "awake-helix-signer.language";

/** The supported language closest to a BCP 47 tag, or null. */
export function match(tag: string): Language | null {
  const value = tag.trim().toLowerCase().replace(/_/g, "-");
  if (!value) return null;
  if (value.startsWith("zh")) {
    if (/-(hant|tw|hk|mo)\b/.test(value)) return "zh-Hant";
    return "zh-Hans";
  }
  const base = value.split("-")[0];
  return (LANGUAGES as readonly string[]).includes(base) ? (base as Language) : null;
}

/** The first supported language among the user's preferences (English otherwise). */
export function detect(preferences: readonly string[]): Language {
  for (const tag of preferences) {
    const found = match(tag);
    if (found) return found;
  }
  return "en";
}

function stored(): Language | null {
  try {
    const value = localStorage.getItem(STORAGE);
    return value && (LANGUAGES as readonly string[]).includes(value) ? (value as Language) : null;
  } catch {
    return null;
  }
}

let language: Language = "en";
const listeners = new Set<() => void>();

export function initLanguage(): Language {
  const preferences = typeof navigator === "undefined" ? [] : [...(navigator.languages ?? []), navigator.language ?? ""];
  language = stored() ?? detect(preferences);
  applyDocument();
  return language;
}

export function getLanguage(): Language {
  return language;
}

export function setLanguage(value: Language): void {
  language = value;
  try {
    localStorage.setItem(STORAGE, value);
  } catch {
    // Not remembered; the choice still applies now.
  }
  applyDocument();
  listeners.forEach((listener) => listener());
}

export function onLanguage(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function applyDocument(): void {
  if (typeof document !== "undefined") {
    document.documentElement.lang = language;
    document.title = DICTIONARIES[language]["app.title"];
  }
}

/** A value a text names: shown as is, or a message translated on its own. */
export type Value = string | number | Msg;
export type Params = Record<string, Value>;

/** A translated text and the untranslated details it carries (English or
 * website texts that have no translation; the page shows them apart, marked
 * as raw data). */
export interface Parts {
  text: string;
  raw: string[];
}

/** Fill {placeholders} of a template. */
export function format(template: string, params: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => (name in params ? String(params[name]) : whole));
}

function isMsg(value: unknown): value is Msg {
  return !!value && typeof value === "object" && "code" in value && "text" in value;
}

function has(key: string): boolean {
  return key in en;
}

/** Translate a template and its nested messages; `detail` params are raw. */
export function tParts(key: Key | string, params: Params = {}): Parts {
  const table = DICTIONARIES[language] as Record<string, string>;
  const template = table[key] ?? (en as Record<string, string>)[key] ?? key;
  const raw: string[] = [];
  const values: Record<string, string | number> = {};
  for (const [name, value] of Object.entries(params)) {
    if (isMsg(value)) {
      const parts = msgParts(value);
      values[name] = parts.text;
      raw.push(...parts.raw);
    } else if (name === "detail") {
      if (String(value)) raw.push(String(value));
    } else {
      values[name] = value;
    }
  }
  return { text: format(template, values), raw };
}

/** The text of a key in the current language (falls back to English, then the key). */
export function t(key: Key | string, params?: Params): string {
  return tParts(key, params).text;
}

/** A message of the core or the backend in the current language. */
export function msgParts(msg: Msg): Parts {
  if (msg.code === "website" && msg.site) return siteParts(msg.site);
  if (msg.code.startsWith("ui:")) return tParts(msg.code.slice(3), msg.params);
  if (has(`core.${msg.code}`)) return tParts(`core.${msg.code}`, msg.params);
  // No code of its own: a headline of its kind, and the English text as the detail.
  const headline = has(`kind.${msg.code}`) ? `kind.${msg.code}` : "kind.other";
  return { text: t(headline), raw: [msg.text] };
}

export function msgText(msg: Msg): string {
  const parts = msgParts(msg);
  return [parts.text, ...parts.raw].join(" ");
}

/** What the website said: its code translated here, else its own text. */
function siteParts(site: SiteText): Parts {
  const key = `site.${site.code}`;
  if (site.code && has(key)) return tParts(key, siteParams(site.params));
  if (language === "zh-Hant") return { text: site.zh || site.en, raw: [] };
  if (language === "en") return { text: site.en || site.zh, raw: [] };
  const own = language === "zh-Hans" ? site.zh || site.en : site.en || site.zh;
  return { text: t("site.untranslated"), raw: [own] };
}

const DATE_PARAMS = new Set(["min", "max", "next"]);

function siteParams(params: Record<string, unknown>): Params {
  const values: Params = {};
  const dates = typeof params.next === "number";
  for (const [name, value] of Object.entries(params)) {
    if (dates && DATE_PARAMS.has(name) && typeof value === "number") values[name] = formatDate(value, "UTC") + " UTC";
    else if (name === "unit") values[name] = unitName(String(value));
    else if (typeof value === "number") values[name] = formatNumber(value);
    else values[name] = String(value ?? "");
  }
  if (typeof params.field === "string") {
    const key = `site.field.${params.field}`;
    values.field = has(key) ? t(key, values) : params.field;
  }
  return values;
}

/** A cap unit: token symbols stay, "lock IDs" is translated. */
export function unitName(unit: string): string {
  return unit === "lock IDs" ? t("unit.lockIds") : unit;
}

/** The BCP 47 locale of the current language. */
export function locale(): string {
  return language;
}

/** A whole number in the current language. */
export function formatNumber(value: number): string {
  return new Intl.NumberFormat(locale(), { maximumFractionDigits: 0 }).format(value);
}

/** A Unix time as date and time in the current language, in UTC or local time. */
export function formatDate(seconds: number, zone: "UTC" | "local"): string {
  return new Intl.DateTimeFormat(locale(), {
    dateStyle: "medium",
    timeStyle: "medium",
    hourCycle: "h23",
    ...(zone === "UTC" ? { timeZone: "UTC" } : {}),
  }).format(new Date(seconds * 1000));
}

/** "<utc> UTC (local <local>)" in the current language. */
export function formatWhen(seconds: number): string {
  return t("common.when", { utc: formatDate(seconds, "UTC"), local: formatDate(seconds, "local") });
}

/** Placeholders a template uses, sorted (for the completeness tests). */
export function placeholders(template: string): string[] {
  return [...template.matchAll(/\{(\w+)\}/g)].map((found) => found[1]).sort();
}
