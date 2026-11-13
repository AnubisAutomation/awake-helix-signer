// Six languages; the default follows the OS/browser language, the switcher's
// choice is remembered on this device (a UI preference, never a secret).
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

/** Fill {placeholders} of a template. */
export function format(template: string, params: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => (name in params ? String(params[name]) : whole));
}

/** The text of a key in the current language (falls back to English, then the key). */
export function t(key: Key | string, params?: Record<string, string | number>): string {
  const table = DICTIONARIES[language] as Record<string, string>;
  const template = table[key] ?? (en as Record<string, string>)[key] ?? key;
  return format(template, params);
}

/** Placeholders a template uses, sorted (for the completeness tests). */
export function placeholders(template: string): string[] {
  return [...template.matchAll(/\{(\w+)\}/g)].map((found) => found[1]).sort();
}
