import { actionOf, classify, firstLink, short, tokenLink } from "../src/links";

const token = "A".repeat(32);

describe("classify", () => {
  it("recognises every link action", () => {
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
    expect(classify("awakehelix://steal?x=1")).toEqual({ kind: "invalid", reason: "action" });
    expect(classify("short")).toEqual({ kind: "invalid", reason: "token" });
    expect(classify("has spaces in it but is long enough")).toEqual({ kind: "invalid", reason: "token" });
  });
});

describe("helpers", () => {
  it("finds the first awakehelix URL in a deep-link event", () => {
    expect(firstLink(["https://x", "awakehelix://grants", "awakehelix://sign"])).toBe("awakehelix://grants");
    expect(firstLink([])).toBeNull();
    expect(firstLink(null)).toBeNull();
  });

  it("builds a sign link for a pasted token", () => {
    expect(tokenLink(token)).toBe(`awakehelix://sign?plan=${token}`);
    expect(tokenLink(token, "https://a.example")).toBe(`awakehelix://sign?plan=${token}&api=https%3A%2F%2Fa.example`);
    expect(actionOf(tokenLink(token))).toBe("sign");
  });

  it("shortens hex", () => {
    expect(short("0x70f6c48e3afc7e499ff2329d698474fd293626bc")).toBe("0x70f6…26bc");
    expect(short("")).toBe("-");
    expect(short("0x1234")).toBe("0x1234");
  });
});
