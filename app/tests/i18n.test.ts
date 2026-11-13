import { en } from "../src/i18n/en";
import { DICTIONARIES, LANGUAGES, detect, format, match, placeholders, setLanguage, t } from "../src/i18n";

const keys = Object.keys(en).sort();

describe("dictionaries", () => {
  it.each(LANGUAGES)("%s has exactly the English keys", (language) => {
    expect(Object.keys(DICTIONARIES[language]).sort()).toEqual(keys);
  });

  it.each(LANGUAGES)("%s has no empty text and the same {placeholders}", (language) => {
    const table = DICTIONARIES[language] as Record<string, string>;
    for (const key of keys) {
      expect(table[key].trim(), `${language} ${key}`).not.toBe("");
      expect(placeholders(table[key]), `${language} ${key}`).toEqual(placeholders((en as Record<string, string>)[key]));
    }
  });

  it("keeps the words that must be typed untranslated", () => {
    for (const language of LANGUAGES) {
      const table = DICTIONARIES[language];
      expect(table["grants.type"]).toContain("REVOKE");
      expect(table["grants.mustType"]).toContain("REVOKE");
      expect(table["grants.confirmPrompt"]).toContain("REVOKE");
    }
  });

  it("is really translated (no language is a copy of English)", () => {
    for (const language of LANGUAGES.filter((item) => item !== "en")) {
      const table = DICTIONARIES[language] as Record<string, string>;
      const same = keys.filter((key) => table[key] === (en as Record<string, string>)[key] && !/^[{}\w\s.:/()-]*$/.test(table[key]));
      expect(same.length, `${language}: ${same.join(", ")}`).toBeLessThan(5);
    }
  });

  it("names the website's own button in each language", () => {
    expect(DICTIONARIES["zh-Hant"]["grants.help"]).toContain("用簽署工具授權");
    expect(DICTIONARIES["zh-Hans"]["grants.help"]).toContain("用签名工具授权");
    expect(DICTIONARIES.en["grants.help"]).toContain("Authorize with the signer");
    expect(DICTIONARIES.ja["grants.help"]).toContain("署名ツールで承認");
    expect(DICTIONARIES.ko["grants.help"]).toContain("서명 도구로 승인");
    expect(DICTIONARIES.es["grants.help"]).toContain("Autorizar con el firmador");
  });
});

describe("language detection", () => {
  it.each([
    ["zh-TW", "zh-Hant"],
    ["zh-HK", "zh-Hant"],
    ["zh-Hant-TW", "zh-Hant"],
    ["zh_TW", "zh-Hant"],
    ["zh-CN", "zh-Hans"],
    ["zh-Hans", "zh-Hans"],
    ["zh", "zh-Hans"],
    ["ja-JP", "ja"],
    ["ko-KR", "ko"],
    ["es-419", "es"],
    ["en-GB", "en"],
  ])("%s -> %s", (tag, expected) => {
    expect(match(tag)).toBe(expected);
  });

  it("takes the first supported preference and falls back to English", () => {
    expect(detect(["de-DE", "ko-KR", "en"])).toBe("ko");
    expect(detect(["de-DE", "fr"])).toBe("en");
    expect(detect([])).toBe("en");
  });
});

describe("t()", () => {
  afterEach(() => setLanguage("en"));

  it("fills placeholders and switches language", () => {
    expect(t("key.loaded", { address: "0xabc" })).toBe("Key loaded: 0xabc");
    setLanguage("zh-Hant");
    expect(t("key.loaded", { address: "0xabc" })).toBe("已載入私鑰：0xabc");
    expect(document.documentElement.lang).toBe("zh-Hant");
  });

  it("leaves unknown placeholders and keys visible", () => {
    expect(format("{a} {b}", { a: 1 })).toBe("1 {b}");
    expect(t("no.such.key")).toBe("no.such.key");
  });
});
