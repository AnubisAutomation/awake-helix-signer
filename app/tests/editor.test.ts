import {
  baseUnits,
  buildRequest,
  combineExpiry,
  EditError,
  expiryParts,
  fieldsOf,
  isDirty,
  outOfRange,
  parseCalls,
  requestOf,
  sameRequest,
  zoneOf,
  type EditorPlan,
} from "../src/editor";

const plan: EditorPlan = {
  validUntil: 1794816462, // 2026-11-16 08:07:42 UTC
  remainingCalls: 256,
  bounds: { validUntil: { min: 1794000000, max: 1801000000 }, remainingCalls: { min: 2, max: 4096 } },
  rules: [
    { index: 0, method: "approve", unit: "DAI", decimals: 18, maxPerCall: "10", maxPerDay: "10", bounds: { maxPerCall: { min: "10", max: "20" }, maxPerDay: { min: "10", max: "40" } } },
    { index: 1, method: "participate", unit: "DAI", decimals: 18, maxPerCall: "10", maxPerDay: "10" },
  ],
};

function code(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof EditError) return error.key;
    throw error;
  }
  return "ok";
}

describe("expiry", () => {
  it("combines a date, a time and a zone like custom.combine_expiry", () => {
    expect(combineExpiry("2026-11-16", "08:07:42", "UTC")).toBe(1794816462);
    expect(combineExpiry("2026-11-16", "16:07:42", "Asia/Taipei")).toBe(1794816462);
    expect(combineExpiry("2026-11-16", "16:07:42", "+08:00")).toBe(1794816462);
    expect(combineExpiry("2026-11-16", "16:07:42", "+0800")).toBe(1794816462);
    expect(combineExpiry("2026-11-16", "03:07:42", "America/New_York")).toBe(1794816462);
    expect(combineExpiry("2026-7-4", "9:00", "Europe/Madrid")).toBe(Date.UTC(2026, 6, 4, 7, 0, 0) / 1000);
  });

  it("handles a summer-time change in an IANA zone", () => {
    // 2026-03-08 is the US spring-forward day: 12:00 is EDT (UTC-4).
    expect(combineExpiry("2026-03-08", "12:00", "America/New_York")).toBe(Date.UTC(2026, 2, 8, 16) / 1000);
    expect(combineExpiry("2026-03-07", "12:00", "America/New_York")).toBe(Date.UTC(2026, 2, 7, 17) / 1000);
  });

  it("uses this computer's zone for Local", () => {
    const local = new Date(2026, 10, 16, 16, 7, 42).getTime() / 1000;
    expect(combineExpiry("2026-11-16", "16:07:42", "Local")).toBe(local);
    expect(combineExpiry("2026-11-16", "16:07:42", "")).toBe(local);
  });

  it("refuses malformed or impossible values", () => {
    expect(code(() => combineExpiry("16/11/2026", "08:00", "UTC"))).toBe("edit.badDate");
    expect(code(() => combineExpiry("2026-11-16", "8pm", "UTC"))).toBe("edit.badTime");
    expect(code(() => combineExpiry("2026-02-30", "08:00", "UTC"))).toBe("edit.notReal");
    expect(code(() => combineExpiry("2026-11-16", "24:00", "UTC"))).toBe("edit.notReal");
    expect(code(() => combineExpiry("2026-11-16", "08:00", "Mars/Olympus"))).toBe("edit.unknownZone");
    expect(code(() => combineExpiry("2026-11-16", "08:00", "+15:00"))).toBe("edit.offsetRange");
    expect(code(() => zoneOf("+08:75"))).toBe("edit.offsetRange");
  });

  it("splits a Unix time back into fields that round-trip", () => {
    expect(expiryParts(1794816462, "UTC")).toEqual({ date: "2026-11-16", time: "08:07:42" });
    expect(expiryParts(1794816420, "Asia/Tokyo")).toEqual({ date: "2026-11-16", time: "17:07" });
    expect(expiryParts(1794816462, "-03:30")).toEqual({ date: "2026-11-16", time: "04:37:42" });
    for (const zone of ["UTC", "Local", "Asia/Taipei", "America/Los_Angeles", "+05:45"]) {
      const { date, time } = expiryParts(plan.validUntil, zone);
      expect(combineExpiry(date, time, zone)).toBe(plan.validUntil);
    }
  });
});

describe("numbers", () => {
  it("parses whole call counts", () => {
    expect(parseCalls(" 256 ")).toBe(256);
    expect(code(() => parseCalls("1.5"))).toBe("edit.badCalls");
    expect(code(() => parseCalls("-1"))).toBe("edit.badCalls");
    expect(code(() => parseCalls("1234567890"))).toBe("edit.badCalls");
  });

  it("parses exact decimal amounts into base units", () => {
    expect(baseUnits("10", 18, "1")).toBe(10n * 10n ** 18n);
    expect(baseUnits("10.000", 18, "1")).toBe(10n * 10n ** 18n);
    expect(baseUnits("0.5", 6, "1")).toBe(500000n);
    expect(baseUnits(".25", 2, "1")).toBe(25n);
    expect(baseUnits("7.", 0, "1")).toBe(7n);
    expect(code(() => baseUnits("0", 18, "1"))).toBe("edit.notPositive");
    expect(code(() => baseUnits("0.0000001", 6, "1"))).toBe("edit.tooPrecise");
    expect(code(() => baseUnits("1e3", 18, "1"))).toBe("edit.badAmount");
    expect(code(() => baseUnits("-5", 18, "1"))).toBe("edit.badAmount");
    expect(code(() => baseUnits("", 18, "1"))).toBe("edit.badAmount");
    expect(code(() => baseUnits("1,5", 18, "1"))).toBe("edit.badAmount");
  });
});

describe("requests", () => {
  it("shows the plan unchanged and is not dirty", () => {
    const fields = fieldsOf(plan, "UTC");
    expect(fields).toMatchObject({ date: "2026-11-16", time: "08:07:42", calls: "256" });
    expect(buildRequest(plan, fields)).toEqual(requestOf(plan));
    expect(isDirty(plan, fields)).toBe(false);
    expect(isDirty(plan, { ...fields, rules: [{ maxPerCall: "10.0", maxPerDay: "10" }, fields.rules[1]] })).toBe(false);
  });

  it("builds the complete customize request from edited fields", () => {
    const fields = { ...fieldsOf(plan, "Asia/Taipei"), calls: "200", rules: [{ maxPerCall: "15", maxPerDay: "30" }, { maxPerCall: "10", maxPerDay: "10" }] };
    const request = buildRequest(plan, fields);
    expect(request).toEqual({
      validUntil: plan.validUntil,
      remainingCalls: 200,
      rules: [
        { index: 0, maxPerCall: "15", maxPerDay: "30" },
        { index: 1, maxPerCall: "10", maxPerDay: "10" },
      ],
    });
    expect(isDirty(plan, fields)).toBe(true);
    expect(sameRequest(plan, request, requestOf(plan))).toBe(false);
  });

  it("counts a malformed field as a change (Sign stays disabled)", () => {
    const fields = { ...fieldsOf(plan, "UTC"), calls: "lots" };
    expect(isDirty(plan, fields)).toBe(true);
    expect(code(() => buildRequest(plan, fields))).toBe("edit.badCalls");
  });

  it("warns about values outside the website's ranges", () => {
    const fields = { ...fieldsOf(plan, "UTC"), calls: "5000", rules: [{ maxPerCall: "25", maxPerDay: "30" }, { maxPerCall: "10", maxPerDay: "10" }] };
    const problems = outOfRange(plan, buildRequest(plan, fields)).map((problem) => problem.key);
    expect(problems).toEqual(["edit.callsRange", "edit.capRange"]);
    expect(outOfRange(plan, requestOf(plan))).toEqual([]);
    const late = { ...fieldsOf(plan, "UTC"), date: "2027-12-31" };
    expect(outOfRange(plan, buildRequest(plan, late)).map((problem) => problem.key)).toEqual(["edit.expiryRange"]);
  });
});
