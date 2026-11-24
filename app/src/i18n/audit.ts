// Language audit of what is on screen (used by the tests and by the app's
// --selftest): every visible text and label must come from the selected
// language's table, and no English word of the English table may show in
// another language. Data is exempt: addresses, hashes, numbers, dates, URLs,
// file names, and elements marked `data-raw` (values from the chain or the
// website, and untranslated details shown apart on purpose).
import { en } from "./en";
import { DICTIONARIES, NAMES, type Language } from "./index";

export interface Leak {
  language: Language;
  text: string;
  reason: "not in the table" | "English word";
  word?: string;
}

/** Words that are names, not English (brands, tokens, words to type, standards). */
const ALLOWED = new Set([
  // Brands and the words the user types.
  "awake", "helix", "anubis", "chain", "authorize", "revoke",
  // Standards, tokens, protocols and system names that are data.
  "dai", "lgns", "ailgns", "helix7702", "helix7702account", "utc", "json", "https", "http", "awakehelix",
  "linux", "windows", "macos", "android",
]);

const normalize = (text: string) => text.replace(/\s+/g, " ").trim();

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const patterns = new Map<Language, RegExp[]>();

/** The language's texts as patterns: each {placeholder} matches any value. */
function templates(language: Language): RegExp[] {
  const cached = patterns.get(language);
  if (cached) return cached;
  const list = Object.values(DICTIONARIES[language] as Record<string, string>).map((value) => {
    const parts = normalize(value).split(/\{\w+\}/);
    return new RegExp("^" + parts.map((part) => escape(part).replace(/ /g, "\\s*")).join("[\\s\\S]+?") + "$");
  });
  patterns.set(language, list);
  return list;
}

const DATA = [
  /https?:\/\/[^\s)]+/g, // URLs
  /awakehelix:\/\/\S*/g,
  /0x[0-9a-fA-F…]+/g, // addresses, hashes, short IDs
  /[\w.-]+\.(json|desktop|app|exe|AppImage)\b/g, // file names
  /(~|\/)[\w./~-]+/g, // paths
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, // UUIDs
];

/** Names the core pins for contracts and shows next to their addresses
 * (helix_signer_core::constants::CONTRACT_NAMES): data, like the addresses. */
const CONTRACT_NAMES = [
  "PowerLedger", "HELIX Router", "RocketSwap Router", "Community Vault", "Turbine",
  "New Turbo 2.5x", "New Turbo 4x", "New Turbo Community", "Community Distributor", "Long Staking 360",
  "Long Staking 600", "Energy Staking", "Energy Burner", "Origin Turbine", "Burn Bond Ranking Reward",
  "Burn Bond", "Burn Fixed",
].sort((left, right) => right.length - left.length); // "Origin Turbine" before "Turbine"

function stripData(text: string): string {
  let rest = text;
  for (const pattern of DATA) rest = rest.replace(pattern, " ");
  for (const name of Object.values(NAMES)) rest = rest.split(name).join(" ");
  for (const name of CONTRACT_NAMES) rest = rest.split(name).join(" ");
  return rest;
}

/** Whether a text is only data (numbers, dates, hex, URLs, punctuation). */
export function isData(text: string): boolean {
  return /^[\s\d.,:;/\-+()#%…·×=<>|'"[\]_]*$/u.test(stripData(text));
}

const deniedCache = new Map<Language, Set<string>>();

/** English words of the English table that the language's own table never uses. */
export function deniedWords(language: Language): Set<string> {
  const cached = deniedCache.get(language);
  if (cached) return cached;
  const words = (texts: string[]) =>
    new Set(texts.flatMap((text) => text.replace(/\{\w+\}/g, " ").toLowerCase().match(/[a-z]{4,}/g) ?? []));
  const own = words(Object.values(DICTIONARIES[language] as Record<string, string>));
  const denied = new Set([...words(Object.values(en))].filter((word) => !own.has(word) && !ALLOWED.has(word)));
  deniedCache.set(language, denied);
  return denied;
}

function visible(element: Element | null): boolean {
  for (let node = element; node; node = node.parentElement) {
    if ((node as HTMLElement).hidden || node.hasAttribute("data-raw")) return false;
    if (["SCRIPT", "STYLE", "DATALIST", "TEMPLATE"].includes(node.tagName)) return false;
    if (node.tagName === "DIALOG" && !node.hasAttribute("open")) return false;
  }
  return true;
}

/** Visible texts and labels under a root, with where they are. */
export function shownTexts(root: Element): string[] {
  const texts: string[] = [];
  const walker = root.ownerDocument.createTreeWalker(root, 4 /* NodeFilter.SHOW_TEXT */);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = normalize(node.textContent ?? "");
    if (text && visible(node.parentElement)) texts.push(text);
  }
  for (const element of root.querySelectorAll("[placeholder], [aria-label], [title], [data-label]")) {
    if (!visible(element)) continue;
    for (const name of ["placeholder", "aria-label", "title", "data-label"]) {
      const value = normalize(element.getAttribute(name) ?? "");
      if (value) texts.push(value);
    }
  }
  return texts;
}

/** Everything on screen that is not in the selected language. */
export function audit(root: Element, language: Language): Leak[] {
  const leaks: Leak[] = [];
  const own = templates(language);
  const denied = language === "en" ? new Set<string>() : deniedWords(language);
  const texts = shownTexts(root);
  const title = normalize(root.ownerDocument.title);
  if (title) texts.push(title);
  for (const text of texts) {
    if (!isData(text) && !own.some((pattern) => pattern.test(text))) leaks.push({ language, text, reason: "not in the table" });
    for (const word of stripData(text).toLowerCase().match(/[a-z]{4,}/g) ?? []) {
      if (denied.has(word)) leaks.push({ language, text, reason: "English word", word });
    }
  }
  return leaks;
}
