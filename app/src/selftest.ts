// Packaging self-test (`anubisauto-signer-app --selftest`): the built app
// loads its page in the real webview, renders every page in every language
// and opens sample links through the real backend and core link parser.
// Nothing is signed and nothing is sent anywhere.
import { api } from "./api";
import { closeRequest, handleUrl, setTab, store } from "./app";
import { en } from "./i18n/en";
import { DICTIONARIES, LANGUAGES, getLanguage, placeholders, setLanguage } from "./i18n";
import { audit } from "./i18n/audit";
import type { Shell } from "./views/shell";

export async function selftest(shell: Shell): Promise<{ ok: boolean; detail: string }> {
  const problems: string[] = [];
  const check = (condition: boolean, problem: string) => {
    if (!condition) problems.push(problem);
  };
  for (const language of LANGUAGES) {
    const table = DICTIONARIES[language] as Record<string, string>;
    for (const key of Object.keys(en)) {
      const value = table[key];
      check(typeof value === "string" && value.length > 0, `${language}: missing ${key}`);
      if (value) check(placeholders(value).join() === placeholders((en as Record<string, string>)[key]).join(), `${language}: placeholders of ${key}`);
    }
  }
  const original = getLanguage();
  for (const language of LANGUAGES) {
    setLanguage(language);
    for (const tab of ["request", "grants", "computer"] as const) {
      setTab(tab);
      check(shell.root.querySelector(`[data-testid=page-${tab}]:not([hidden])`) !== null, `${language}: page ${tab} hidden`);
      // Nothing on the page may come from another language.
      for (const leak of audit(document.body, language).slice(0, 3)) problems.push(`${language}: ${tab}: ${leak.reason}: ${leak.text.slice(0, 80)}`);
    }
  }
  setLanguage(original);
  const token = "S".repeat(32);
  await handleUrl(`anubisauto://sign?plan=${token}`);
  check(store.request.phase === "ready", `sign link: ${store.request.phase}`);
  check(store.link?.official === true, "sign link: official website");
  await handleUrl(`anubisauto://revoke?plan=${"R".repeat(32)}`);
  check(store.request.phase === "ready" && store.link?.action === "revoke", "revoke link");
  await handleUrl("anubisauto://grants");
  check(store.tab === "grants" && store.link?.action === "grants", "grants link");
  // Links of the signers before 0.7.0 still open the app.
  await handleUrl(`awakehelix://revoke?plan=${"L".repeat(32)}`);
  check(store.request.phase === "ready" && store.link?.action === "revoke", "legacy revoke link");
  await handleUrl("anubisauto://sign?plan=x&api=https://evil.example");
  check(store.request.phase === "empty" && store.status?.key === "link.refused", "foreign website refused");
  await closeRequest();
  const setup = await api.setupStatus();
  check(typeof setup.os === "string", "setup status");
  const info = await api.appInfo();
  return { ok: problems.length === 0, detail: problems.length ? problems.join("; ") : `ui ok (${info.version}, ${info.os}/${info.arch}, ${LANGUAGES.length} languages)` };
}
