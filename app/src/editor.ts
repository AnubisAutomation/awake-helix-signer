// The grant editor's values: parse what the owner typed into a complete
// customize request (the same request the core's custom.rs builds for the
// CLI). These checks only catch typing mistakes early; the backend and
// the core verify the website's re-planned grant against exactly this
// request before anything can be signed.

export const LOCAL = "Local";
export const UTC = "UTC";
export const ZONES = [
  LOCAL, UTC, "Asia/Taipei", "Asia/Shanghai", "Asia/Hong_Kong", "Asia/Singapore", "Asia/Tokyo",
  "Asia/Seoul", "Europe/London", "Europe/Paris", "Europe/Madrid", "America/New_York", "America/Chicago",
  "America/Los_Angeles", "America/Mexico_City", "America/Sao_Paulo", "Australia/Sydney",
];

/** A typing mistake, with a message key and its parameters for the UI. */
export class EditError extends Error {
  constructor(
    public readonly key: string,
    public readonly params: Record<string, string | number> = {},
  ) {
    super(key);
  }
}

export interface Range {
  min: number | string;
  max: number | string;
}

export interface EditorRule {
  index: number;
  method: string;
  unit: string;
  decimals: number;
  maxPerCall: string;
  maxPerDay: string;
  bounds?: { maxPerCall?: Range; maxPerDay?: Range };
}

/** What the backend sends for a verified grant plan. */
export interface EditorPlan {
  validUntil: number;
  remainingCalls: number;
  bounds?: { validUntil?: Range; remainingCalls?: Range };
  rules: EditorRule[];
}

export interface RuleRequest {
  index: number;
  maxPerCall: string;
  maxPerDay: string;
}

/** The complete customize request (every value is sent, changed or not). */
export interface CustomizeRequest {
  validUntil: number;
  remainingCalls: number;
  rules: RuleRequest[];
}

export interface Fields {
  date: string;
  time: string;
  zone: string;
  calls: string;
  rules: { maxPerCall: string; maxPerDay: string }[];
}

const OFFSET = /^([+-])(\d{1,2})(?::?(\d{2}))?$/;
const DATE = /^(\d{4})-(\d{1,2})-(\d{1,2})$/;
const TIME = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/;

type Zone = { kind: "local" } | { kind: "fixed"; minutes: number } | { kind: "iana"; name: string };

/** Resolve a time zone: Local, UTC, an IANA name or an offset like +08:00. */
export function zoneOf(name: string): Zone {
  const text = name.trim();
  if (!text || text.toLowerCase() === LOCAL.toLowerCase()) return { kind: "local" };
  if (["UTC", "Z", "GMT"].includes(text.toUpperCase())) return { kind: "fixed", minutes: 0 };
  const offset = OFFSET.exec(text);
  if (offset) {
    const hours = Number(offset[2]);
    const minutes = Number(offset[3] ?? 0);
    if (hours > 14 || minutes > 59) throw new EditError("edit.offsetRange", { zone: text });
    const total = hours * 60 + minutes;
    return { kind: "fixed", minutes: offset[1] === "-" ? -total : total };
  }
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: text });
  } catch {
    throw new EditError("edit.unknownZone", { zone: text });
  }
  return { kind: "iana", name: text };
}

interface Wall {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

/** Wall-clock fields of a Unix time in an IANA zone. */
function wallIn(seconds: number, zone: string): Wall {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(seconds * 1000));
  const get = (type: string) => Number(parts.find((part) => part.type === type)?.value ?? 0);
  return { year: get("year"), month: get("month"), day: get("day"), hour: get("hour") % 24, minute: get("minute"), second: get("second") };
}

const wallSeconds = (wall: Wall) =>
  Date.UTC(wall.year, wall.month - 1, wall.day, wall.hour, wall.minute, wall.second) / 1000;

/** Offset of an IANA zone at a Unix time, in seconds. */
function ianaOffset(seconds: number, zone: string): number {
  return wallSeconds(wallIn(seconds, zone)) - seconds;
}

/** Unix time of a date, a wall-clock time and a time zone (like custom.combine_expiry). */
export function combineExpiry(date: string, time: string, zone: string): number {
  const day = DATE.exec(date.trim());
  const moment = TIME.exec(time.trim());
  if (!day) throw new EditError("edit.badDate", { value: date.trim() });
  if (!moment) throw new EditError("edit.badTime", { value: time.trim() });
  const wall: Wall = {
    year: Number(day[1]),
    month: Number(day[2]),
    day: Number(day[3]),
    hour: Number(moment[1]),
    minute: Number(moment[2]),
    second: Number(moment[3] ?? 0),
  };
  const naive = Date.UTC(wall.year, wall.month - 1, wall.day, wall.hour, wall.minute, wall.second);
  const check = new Date(naive);
  if (
    check.getUTCFullYear() !== wall.year || check.getUTCMonth() !== wall.month - 1 || check.getUTCDate() !== wall.day ||
    wall.hour > 23 || wall.minute > 59 || wall.second > 59
  ) {
    throw new EditError("edit.notReal", { value: `${date.trim()} ${time.trim()}` });
  }
  const resolved = zoneOf(zone);
  if (resolved.kind === "local") {
    return Math.floor(new Date(wall.year, wall.month - 1, wall.day, wall.hour, wall.minute, wall.second).getTime() / 1000);
  }
  const guess = naive / 1000;
  if (resolved.kind === "fixed") return guess - resolved.minutes * 60;
  // Two passes settle the offset across a DST change (like zoneinfo's fold=0).
  let result = guess - ianaOffset(guess, resolved.name);
  result = guess - ianaOffset(result, resolved.name);
  return result;
}

const pad = (value: number) => String(value).padStart(2, "0");

/** Date and time fields of a Unix time in one zone (HH:MM:SS only when seconds are set). */
export function expiryParts(seconds: number, zone: string): { date: string; time: string } {
  const resolved = zoneOf(zone);
  let wall: Wall;
  if (resolved.kind === "local") {
    const moment = new Date(seconds * 1000);
    wall = {
      year: moment.getFullYear(), month: moment.getMonth() + 1, day: moment.getDate(),
      hour: moment.getHours(), minute: moment.getMinutes(), second: moment.getSeconds(),
    };
  } else if (resolved.kind === "fixed") {
    const moment = new Date((seconds + resolved.minutes * 60) * 1000);
    wall = {
      year: moment.getUTCFullYear(), month: moment.getUTCMonth() + 1, day: moment.getUTCDate(),
      hour: moment.getUTCHours(), minute: moment.getUTCMinutes(), second: moment.getUTCSeconds(),
    };
  } else {
    wall = wallIn(seconds, resolved.name);
  }
  const time = `${pad(wall.hour)}:${pad(wall.minute)}` + (wall.second ? `:${pad(wall.second)}` : "");
  return { date: `${wall.year}-${pad(wall.month)}-${pad(wall.day)}`, time };
}

/** A whole number of calls. */
export function parseCalls(text: string): number {
  const value = text.trim();
  if (!/^\d{1,9}$/.test(value)) throw new EditError("edit.badCalls", { value });
  return Number(value);
}

/** A positive decimal amount in exact base units. */
export function baseUnits(text: string, decimals: number, label: string): bigint {
  const value = text.trim();
  const match = /^\+?(\d*)(?:\.(\d*))?$/.exec(value);
  if (!match || (!match[1] && !match[2])) throw new EditError("edit.badAmount", { label, value });
  const whole = match[1] || "0";
  const fraction = (match[2] ?? "").replace(/0+$/, "");
  if (fraction.length > decimals) throw new EditError("edit.tooPrecise", { label, decimals });
  const units = BigInt(whole) * 10n ** BigInt(decimals) + BigInt((fraction || "0").padEnd(decimals, "0") || "0");
  if (units <= 0n) throw new EditError("edit.notPositive", { label });
  return units;
}

/** Editor fields showing a plan in a time zone. */
export function fieldsOf(plan: EditorPlan, zone: string): Fields {
  const { date, time } = expiryParts(plan.validUntil, zone);
  return {
    date,
    time,
    zone,
    calls: String(plan.remainingCalls),
    rules: plan.rules.map((rule) => ({ maxPerCall: rule.maxPerCall, maxPerDay: rule.maxPerDay })),
  };
}

/** The request a plan describes as it is now. */
export function requestOf(plan: EditorPlan): CustomizeRequest {
  return {
    validUntil: plan.validUntil,
    remainingCalls: plan.remainingCalls,
    rules: plan.rules.map((rule) => ({ index: rule.index, maxPerCall: rule.maxPerCall, maxPerDay: rule.maxPerDay })),
  };
}

/** Parse the fields into a complete customize request; throws EditError on a typing mistake. */
export function buildRequest(plan: EditorPlan, fields: Fields): CustomizeRequest {
  const rules = plan.rules.map((rule, position) => {
    const typed = fields.rules[position] ?? { maxPerCall: "", maxPerDay: "" };
    const label = String(position + 1);
    baseUnits(typed.maxPerCall, rule.decimals, `${label}/call`);
    baseUnits(typed.maxPerDay, rule.decimals, `${label}/day`);
    return { index: rule.index, maxPerCall: typed.maxPerCall.trim(), maxPerDay: typed.maxPerDay.trim() };
  });
  return {
    validUntil: combineExpiry(fields.date, fields.time, fields.zone),
    remainingCalls: parseCalls(fields.calls),
    rules,
  };
}

/** Whether two requests mean the same values (10 equals 10.0). */
export function sameRequest(plan: EditorPlan, left: CustomizeRequest, right: CustomizeRequest): boolean {
  if (left.validUntil !== right.validUntil || left.remainingCalls !== right.remainingCalls) return false;
  if (left.rules.length !== right.rules.length) return false;
  return left.rules.every((rule, position) => {
    const decimals = plan.rules[position]?.decimals ?? 18;
    const other = right.rules[position];
    return (["maxPerCall", "maxPerDay"] as const).every(
      (field) => baseUnits(rule[field], decimals, field) === baseUnits(other[field], decimals, field),
    );
  });
}

/** Whether the fields differ from the plan shown; a malformed field counts as a change. */
export function isDirty(plan: EditorPlan, fields: Fields): boolean {
  try {
    return !sameRequest(plan, buildRequest(plan, fields), requestOf(plan));
  } catch {
    return true;
  }
}

/** Soft checks against the website's ranges (the website has the final word). */
export function outOfRange(plan: EditorPlan, request: CustomizeRequest): EditError[] {
  const problems: EditError[] = [];
  const within = (value: bigint | number, range: Range | undefined, scale: (v: number | string) => bigint) =>
    !range || (BigInt(value) >= scale(range.min) && BigInt(value) <= scale(range.max));
  const plain = (v: number | string) => BigInt(Math.trunc(Number(v)));
  if (!within(request.validUntil, plan.bounds?.validUntil, plain)) problems.push(new EditError("edit.expiryRange"));
  if (!within(request.remainingCalls, plan.bounds?.remainingCalls, plain)) problems.push(new EditError("edit.callsRange"));
  plan.rules.forEach((rule, position) => {
    const typed = request.rules[position];
    const amount = (v: number | string) => baseUnits(String(v), rule.decimals, "bound");
    for (const field of ["maxPerCall", "maxPerDay"] as const) {
      const bound = rule.bounds?.[field];
      if (bound && !within(baseUnits(typed[field], rule.decimals, field), bound, amount)) {
        problems.push(new EditError("edit.capRange", { rule: position + 1 }));
      }
    }
  });
  return problems;
}
