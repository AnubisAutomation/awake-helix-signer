import { actionOf, classify, firstLink, isOurs, LEGACY_SCHEME, SCHEME, SCHEMES, short, tokenLink } from "../src/links";

const token = "A".repeat(32);

describe("classify", () => {
  it("recognises every link action", () => {
    expect(classify(`anubisauto://sign?plan=${token}`)).toEqual({ kind: "link", url: `anubisauto://sign?plan=${token}`, action: "sign" });
    expect(classify(`anubisauto://revoke?plan=${token}&api=https://x`)).toMatchObject({ action: "revoke" });
    expect(classify(`anubisauto://ping?token=${token}`)).toMatchObject({ action: "ping" });
    expect(classify("anubisauto://grants")).toMatchObject({ action: "grants" });
    expect(classify("AnubisAuto://GRANTS?api=https://anubis.sivilization.com")).toMatchObject({ kind: "link", action: "grants" });
    expect(classify("anubisauto:grants")).toMatchObject({ action: "grants" });
  });

  it("still accepts the legacy awakehelix:// links of the signers before 0.7.0", () => {
    expect(SCHEMES).toEqual([SCHEME, LEGACY_SCHEME]);
    expect([SCHEME, LEGACY_SCHEME]).toEqual(["anubisauto", "awakehelix"]);
    expect(classify(`awakehelix://sign?plan=${token}`)).toEqual({ kind: "link", url: `awakehelix://sign?plan=${token}`, action: "sign" });
    expect(classify(`awakehelix://revoke?plan=${token}&api=https://x`)).toMatchObject({ action: "revoke" });
    expect(classify(`awakehelix://ping?token=${token}`)).toMatchObject({ action: "ping" });
    expect(classify("awakehelix://grants")).toMatchObject({ action: "grants" });
    expect(classify("AwakeHelix://GRANTS?api=https://anubis.sivilization.com")).toMatchObject({ kind: "link", action: "grants" });
    expect(classify("awakehelix:grants")).toMatchObject({ action: "grants" });
  });

  it("accepts a bare plan token", () => {
    expect(classify(`  ${token}\n`)).toEqual({ kind: "token", token });
  });

  it("refuses everything else", () => {
    expect(classify("")).toEqual({ kind: "invalid", reason: "empty" });
    expect(classify("https://anubis.sivilization.com/x")).toEqual({ kind: "invalid", reason: "scheme" });
    expect(classify("javascript:alert(1)")).toEqual({ kind: "invalid", reason: "scheme" });
    for (const scheme of SCHEMES) {
      expect(classify(`${scheme}://steal?x=1`)).toEqual({ kind: "invalid", reason: "action" });
      expect(classify(`${scheme}://drain?plan=${token}`)).toEqual({ kind: "invalid", reason: "action" });
    }
    expect(classify("short")).toEqual({ kind: "invalid", reason: "token" });
    expect(classify("has spaces in it but is long enough")).toEqual({ kind: "invalid", reason: "token" });
  });

  it("refuses other schemes and look-alikes", () => {
    for (const url of [
      `anubis://sign?plan=${token}`,
      `anubis-auto://sign?plan=${token}`,
      `anubis.auto://sign?plan=${token}`,
      `anubisautos://sign?plan=${token}`,
      `anubisauto2://sign?plan=${token}`,
      `xanubisauto://sign?plan=${token}`,
      `anubisauto.evil.example://sign?plan=${token}`,
      `anubisauto+evil://sign?plan=${token}`,
      `awake-helix://sign?plan=${token}`,
      `awakehelixx://sign?plan=${token}`,
      `awakehelix-signer://sign?plan=${token}`,
      `helix://sign?plan=${token}`,
      `javascript:anubisauto://sign?plan=${token}`,
    ]) {
      expect(classify(url), url).toEqual({ kind: "invalid", reason: "scheme" });
      expect(actionOf(url), url).toBeNull();
      expect(isOurs(url), url).toBe(false);
    }
    // Cyrillic "\u0430" and "\u0435" in place of the Latin letters: not even a scheme.
    for (const url of [`\u0430nubisauto://sign?plan=${token}`, `awak\u0435helix://sign?plan=${token}`]) {
      expect(classify(url), url).toEqual({ kind: "invalid", reason: "token" });
      expect(actionOf(url), url).toBeNull();
      expect(isOurs(url), url).toBe(false);
    }
    // No scheme at all: neither a link nor a token.
    expect(classify(`anubisauto//sign?plan=${token}`)).toEqual({ kind: "invalid", reason: "token" });
  });
});

describe("helpers", () => {
  it("finds the first of our URLs in a deep-link event", () => {
    expect(firstLink(["https://x", "anubisauto://grants", "anubisauto://sign"])).toBe("anubisauto://grants");
    expect(firstLink(["https://x", "awakehelix://grants", "anubisauto://sign"])).toBe("awakehelix://grants");
    expect(firstLink(["https://x", "anubisautox://grants", "awake-helix://sign"])).toBeNull();
    expect(firstLink([])).toBeNull();
    expect(firstLink(null)).toBeNull();
  });

  it("builds a sign link for a pasted token with the anubisauto:// scheme", () => {
    expect(tokenLink(token)).toBe(`anubisauto://sign?plan=${token}`);
    expect(tokenLink(token, "https://a.example")).toBe(`anubisauto://sign?plan=${token}&api=https%3A%2F%2Fa.example`);
    expect(actionOf(tokenLink(token))).toBe("sign");
  });

  it("shortens hex", () => {
    expect(short("0x70f6c48e3afc7e499ff2329d698474fd293626bc")).toBe("0x70f6…26bc");
    expect(short("")).toBe("-");
    expect(short("0x1234")).toBe("0x1234");
  });
});
