//! Turn what the owner typed into the values of a customize request, and
//! check the answer.
//!
//! The website re-plans a grant within its bounds (``POST
//! /api/signer/plans/<token>/customize``). The bounds it reports are only
//! hints for the editor; what protects the owner is checked here and in
//! [`crate::plan::verify_grant_plan`]: an answer may change exactly the values
//! that were requested and nothing else.

use jiff::civil::{Date, DateTime, Time};
use jiff::tz::{Offset, TimeZone};
use jiff::Timestamp;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::plan::{amount, amount_digits, unix_now, GrantPlan, Rule};
use crate::pyfmt::{cmp_digits, parse_decimal, str_repr, Parsed};

/// This computer's zone.
pub const LOCAL: &str = "Local";
/// UTC.
pub const UTC_NAME: &str = "UTC";
/// Offered by the editor's time zone box; any other IANA name or +08:00 also works.
pub const ZONES: [&str; 17] = [
    LOCAL,
    UTC_NAME,
    "Asia/Taipei",
    "Asia/Shanghai",
    "Asia/Hong_Kong",
    "Asia/Singapore",
    "Asia/Tokyo",
    "Asia/Seoul",
    "Europe/London",
    "Europe/Paris",
    "Europe/Madrid",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "America/Mexico_City",
    "America/Sao_Paulo",
    "Australia/Sydney",
];
const FORMATS: &str = "YYYY-MM-DD HH:MM [zone], an ISO 8601 time, Unix seconds, or a length such as 30d or 12h";

/// One rule's requested caps (decimal text in the rule's unit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleChange {
    /// 0-based rule index.
    pub index: usize,
    /// Per-call cap, or None to keep it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_per_call: Option<String>,
    /// Per-day cap, or None to keep it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_per_day: Option<String>,
}

/// The body of ``POST .../customize`` under ``"grant"``.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomizeRequest {
    /// New expiry (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<i64>,
    /// New total call count.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remaining_calls: Option<u64>,
    /// Every rule's caps.
    #[serde(default)]
    pub rules: Vec<RuleChange>,
}

fn all_digits(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// A resolved time zone: a fixed offset or a named zone.
fn zone_of(name: &str) -> Result<TimeZone> {
    let text = name.trim();
    if text.is_empty() || text.to_lowercase() == LOCAL.to_lowercase() {
        return Ok(TimeZone::system());
    }
    if ["UTC", "Z", "GMT"].contains(&text.to_uppercase().as_str()) {
        return Ok(TimeZone::UTC);
    }
    if let Some(offset) = parse_offset(text)? {
        return Ok(TimeZone::fixed(offset));
    }
    TimeZone::get(text).map_err(|_| {
        Error::plan(format!(
            "Unknown time zone {}: use a name like Asia/Taipei or an offset like +08:00.",
            str_repr(text)
        ))
    })
}

/// ``^([+-])(\d{1,2})(?::?(\d{2}))?$``.
fn parse_offset(text: &str) -> Result<Option<Offset>> {
    let Some(sign) = text.chars().next().filter(|ch| *ch == '+' || *ch == '-') else { return Ok(None) };
    let rest = &text[1..];
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    let after = &rest[digits.len()..];
    let (hours, minutes) = if after.is_empty() && (1..=2).contains(&digits.len()) {
        (digits.as_str(), "")
    } else if after.is_empty() && (3..=4).contains(&digits.len()) {
        digits.split_at(digits.len() - 2)
    } else if let Some(minutes) = after.strip_prefix(':') {
        if !(1..=2).contains(&digits.len()) || !all_digits(minutes, 2, 2) {
            return Ok(None);
        }
        (digits.as_str(), minutes)
    } else {
        return Ok(None);
    };
    let hours: i32 = hours.parse().unwrap_or(0);
    let minutes: i32 = if minutes.is_empty() { 0 } else { minutes.parse().unwrap_or(0) };
    if hours > 14 || minutes > 59 {
        return Err(Error::plan(format!("The UTC offset {} is out of range.", str_repr(text))));
    }
    let seconds = (hours * 3600 + minutes * 60) * if sign == '-' { -1 } else { 1 };
    Offset::from_seconds(seconds).map(Some).map_err(|_| Error::plan(format!("The UTC offset {} is out of range.", str_repr(text))))
}

fn parse_date(text: &str) -> Option<(i16, i8, i8)> {
    let mut parts = text.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !all_digits(year, 4, 4) || !all_digits(month, 1, 2) || !all_digits(day, 1, 2) {
        return None;
    }
    Some((year.parse().ok()?, month.parse().ok()?, day.parse().ok()?))
}

fn parse_clock(text: &str) -> Option<(i8, i8, i8)> {
    let parts: Vec<&str> = text.split(':').collect();
    if !(2..=3).contains(&parts.len()) || !all_digits(parts[0], 1, 2) || !all_digits(parts[1], 2, 2) {
        return None;
    }
    if parts.len() == 3 && !all_digits(parts[2], 2, 2) {
        return None;
    }
    Some((parts[0].parse().ok()?, parts[1].parse().ok()?, parts.get(2).map(|s| s.parse().unwrap_or(0)).unwrap_or(0)))
}

/// Unix time of a date, a wall-clock time and a time zone.
pub fn combine_expiry(date: &str, clock: &str, zone: &str) -> Result<i64> {
    let (date_text, clock_text) = (date.trim(), clock.trim());
    let day = parse_date(date_text)
        .ok_or_else(|| Error::plan(format!("The expiry date {} must look like 2026-12-31.", str_repr(date_text))))?;
    let moment = parse_clock(clock_text)
        .ok_or_else(|| Error::plan(format!("The expiry time {} must look like 16:30.", str_repr(clock_text))))?;
    let resolved = zone_of(zone)?;
    let impossible = || Error::plan(format!("{date_text} {clock_text} is not a real date and time."));
    if day.0 < 1 {
        return Err(impossible());
    }
    let civil = Date::new(day.0, day.1, day.2).map_err(|_| impossible())?;
    let time = Time::new(moment.0, moment.1, moment.2, 0).map_err(|_| impossible())?;
    let zoned = DateTime::from_parts(civil, time).to_zoned(resolved).map_err(|_| impossible())?;
    Ok(zoned.timestamp().as_second())
}

/// Parse ``--expires``: ``2026-12-31 16:30 Asia/Taipei``,
/// ``2026-12-31T08:30:00Z``, Unix seconds, ``30d`` or ``12h`` (from now). A
/// date and time without a zone is this computer's local time.
pub fn parse_expiry(text: &str, now: Option<i64>) -> Result<i64> {
    let value = text.trim();
    if all_digits(value, 9, 12) {
        return value.parse().map_err(|_| Error::plan("The expiry is not understood."));
    }
    let relative = value.strip_prefix('+').unwrap_or(value);
    let digits: String = relative.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if !digits.is_empty() {
        let unit = relative[digits.len()..].trim_start();
        if unit.eq_ignore_ascii_case("d") || unit.eq_ignore_ascii_case("h") {
            let current = now.unwrap_or_else(|| unix_now() as i64);
            let count: i64 = digits.parse().map_err(|_| Error::plan("The expiry is not understood."))?;
            let step = if unit.eq_ignore_ascii_case("d") { 86400 } else { 3600 };
            return Ok(current + count * step);
        }
    }
    let mut rewritten = value.to_string();
    if let Some(index) = value.find(['T', 't']) {
        if parse_date(&value[..index]).is_some() {
            rewritten = format!("{} {}", &value[..index], &value[index + 1..]);
        }
    }
    let parts: Vec<&str> = rewritten.split_whitespace().collect();
    if (parts.len() == 2 || parts.len() == 3) && parse_date(parts[0]).is_some() {
        let mut clock = parts[1].to_string();
        let mut zone = if parts.len() == 3 { parts[2].to_string() } else { LOCAL.to_string() };
        if parts.len() == 2 {
            if let Some((bare, attached)) = split_attached_zone(parts[1]) {
                clock = bare;
                zone = attached;
            }
        }
        return combine_expiry(parts[0], &clock, &zone);
    }
    Err(Error::plan(format!("The expiry {} is not understood: use {FORMATS}.", str_repr(text))))
}

/// ``(\d{1,2}:\d{2}(?::\d{2})?)(?:\.\d+)?(Z|[+-]\d{1,2}(?::?\d{2})?)``.
fn split_attached_zone(clock: &str) -> Option<(String, String)> {
    let zone_at = clock.find(['Z', '+', '-'])?;
    let (time_part, zone) = clock.split_at(zone_at);
    let bare = match time_part.split_once('.') {
        Some((bare, fraction)) if all_digits(fraction, 1, usize::MAX) => bare,
        Some(_) => return None,
        None => time_part,
    };
    parse_clock(bare)?;
    let zone_ok = zone == "Z" || offset_shape(&zone[1..]);
    zone_ok.then(|| (bare.to_string(), zone.to_string()))
}

/// ``\d{1,2}(?::?\d{2})?`` after the sign of an offset.
fn offset_shape(rest: &str) -> bool {
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    let after = &rest[digits.len()..];
    if after.is_empty() {
        return (1..=4).contains(&digits.len());
    }
    (1..=2).contains(&digits.len()) && after.strip_prefix(':').map(|minutes| all_digits(minutes, 2, 2)).unwrap_or(false)
}

/// Date and time of a Unix time in one zone, for the editor's fields:
/// ``YYYY-MM-DD`` and ``HH:MM`` (``HH:MM:SS`` when the seconds are not zero).
pub fn expiry_parts(seconds: i64, zone: &str) -> Result<(String, String)> {
    let moment = Timestamp::from_second(seconds).map_err(|_| Error::plan("The expiry is out of range."))?.to_zoned(zone_of(zone)?);
    let clock = if moment.second() == 0 { moment.strftime("%H:%M").to_string() } else { moment.strftime("%H:%M:%S").to_string() };
    Ok((moment.strftime("%Y-%m-%d").to_string(), clock))
}

/// Parse a whole number of calls.
pub fn parse_calls(text: &str) -> Result<u64> {
    let value = text.trim();
    if !all_digits(value, 1, 9) {
        return Err(Error::plan(format!("The number of calls {} must be a whole number.", str_repr(value))));
    }
    value.parse().map_err(|_| Error::plan("The number of calls must be a whole number."))
}

/// Parse a decimal amount into exact base units (decimal digits; may exceed 256 bits).
pub fn base_units(text: &str, decimals: u32, label: &str) -> Result<String> {
    let value = match parse_decimal(text.trim()) {
        Some(Parsed::Finite(value)) => value,
        Some(Parsed::Special) => return Err(Error::plan(format!("{label} must be a positive number."))),
        None => return Err(Error::plan(format!("{label} {} must be a decimal number.", str_repr(text.trim())))),
    };
    if value.negative || value.is_zero() {
        return Err(Error::plan(format!("{label} must be a positive number.")));
    }
    let scaled = value.scaleb(decimals as i64);
    if !scaled.is_integral() {
        return Err(Error::plan(format!("{label} has more than {decimals} decimal places.")));
    }
    Ok(scaled.integer_digits())
}

fn u256_equals(value: &U256, digits: &str) -> bool {
    cmp_digits(&value.to_string(), digits) == std::cmp::Ordering::Equal
}

fn rule_index(name: &str, rules: &[Rule]) -> Result<usize> {
    let text = name.trim();
    if all_digits(text, 1, 3) {
        let number: usize = text.parse().unwrap_or(0);
        if number >= 1 && number <= rules.len() {
            return Ok(number - 1);
        }
        return Err(Error::plan(format!("There is no rule {text}: this grant has rules 1 to {}.", rules.len())));
    }
    let matches: Vec<usize> =
        rules.iter().enumerate().filter(|(_, rule)| rule.method().to_lowercase() == text.to_lowercase()).map(|(index, _)| index).collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(Error::plan(format!("No rule is called {}; use a rule number from the summary.", str_repr(text)))),
        _ => {
            let numbers: Vec<String> = matches.iter().map(|index| (index + 1).to_string()).collect();
            Err(Error::plan(format!("Several rules are {text}; use a rule number ({}).", numbers.join(", "))))
        }
    }
}

/// A parsed ``--cap``: rule index, per-call text, per-day text.
pub type Cap = (usize, Option<String>, Option<String>);

/// Parse ``--cap <rule>=<per_call>,<per_day>`` (``1=15,40``, ``approve=15``, ``2=,40``).
pub fn parse_cap(text: &str, rules: &[Rule]) -> Result<Cap> {
    let (rule, values) = match text.split_once('=') {
        Some(split) => split,
        None => (text, ""),
    };
    let (per_call, per_day) = values.split_once(',').unwrap_or((values, ""));
    let (per_call, per_day) = (per_call.trim(), per_day.trim());
    if !text.contains('=') || (per_call.is_empty() && per_day.is_empty()) {
        return Err(Error::plan(format!(
            "--cap {}: use <rule>=<per_call>,<per_day>, for example 1=15,40.",
            str_repr(text)
        )));
    }
    let option = |value: &str| (!value.is_empty()).then(|| value.to_string());
    Ok((rule_index(rule, rules)?, option(per_call), option(per_day)))
}

/// The complete customize request describing a plan as it is now.
pub fn request_of(plan: &GrantPlan) -> CustomizeRequest {
    CustomizeRequest {
        valid_until: Some(plan.valid_until as i64),
        remaining_calls: Some(plan.remaining_calls),
        rules: plan
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RuleChange {
                index,
                max_per_call: Some(amount(&rule.max_amount, rule.unit().1)),
                max_per_day: Some(amount(&rule.max_daily, rule.unit().1)),
            })
            .collect(),
    }
}

/// Apply the owner's changes on top of a plan's current values. A raised
/// per-call cap without a per-day value raises the per-day cap only as far
/// as needed.
pub fn with_changes(plan: &GrantPlan, expires: Option<i64>, calls: Option<u64>, caps: &[Cap]) -> Result<CustomizeRequest> {
    let mut request = request_of(plan);
    if expires.is_some() {
        request.valid_until = expires;
    }
    if calls.is_some() {
        request.remaining_calls = calls;
    }
    for (index, per_call, per_day) in caps {
        let rule = &plan.rules[*index];
        let decimals = rule.unit().1;
        let label = format!("Rule {} ({})", index + 1, rule.method());
        let entry = &mut request.rules[*index];
        if let Some(per_call) = per_call {
            base_units(per_call, decimals, &format!("{label}: the per-call cap"))?;
            entry.max_per_call = Some(per_call.clone());
        }
        if let Some(per_day) = per_day {
            base_units(per_day, decimals, &format!("{label}: the per-day cap"))?;
            entry.max_per_day = Some(per_day.clone());
        } else if let Some(per_call) = per_call {
            let wanted = base_units(per_call, decimals, &label)?;
            let current = rule.max_daily.to_string();
            let larger = if cmp_digits(&wanted, &current) == std::cmp::Ordering::Greater { wanted } else { current };
            entry.max_per_day = Some(amount_digits(&larger, decimals));
        }
    }
    Ok(request)
}

/// Refuse a customize answer that does anything but the requested change.
pub fn check_answer(before: &GrantPlan, after: &GrantPlan, request: &CustomizeRequest) -> Result<()> {
    let changed = |field: &str| Error::plan(format!("The website's new plan changes {field}, which an edit may never change."));
    if before.owner != after.owner {
        return Err(changed("owner"));
    }
    if before.grant_id != after.grant_id {
        return Err(changed("grant_id"));
    }
    if before.session_key != after.session_key {
        return Err(changed("session_key"));
    }
    if before.bot_id != after.bot_id {
        return Err(changed("bot_id"));
    }
    if before.valid_after != after.valid_after {
        return Err(changed("valid_after"));
    }
    if before.implementation != after.implementation {
        return Err(changed("implementation"));
    }
    if before.rules.len() != after.rules.len() {
        return Err(Error::plan("The website's new plan changes the list of rules."));
    }
    if let Some(until) = request.valid_until {
        if after.valid_until as i64 != until {
            return Err(Error::plan("The website's new plan does not have the expiry you asked for."));
        }
    }
    if let Some(calls) = request.remaining_calls {
        if after.remaining_calls != calls {
            return Err(Error::plan("The website's new plan does not have the number of calls you asked for."));
        }
    }
    for (index, (old, new)) in before.rules.iter().zip(&after.rules).enumerate() {
        let fields: [(&str, bool); 7] = [
            ("kind", old.kind != new.kind),
            ("target", old.target != new.target),
            ("token_in", old.token_in != new.token_in),
            ("counterparty", old.counterparty != new.counterparty),
            ("max_secondary", old.max_secondary != new.max_secondary),
            ("min_out_per_in_wad", old.min_out_per_in_wad != new.min_out_per_in_wad),
            ("max_deadline_delay", old.max_deadline_delay != new.max_deadline_delay),
        ];
        if let Some((field, _)) = fields.iter().find(|(_, differs)| *differs) {
            return Err(Error::plan(format!(
                "The website's new plan changes rule {} ({field}), which an edit may never change.",
                index + 1
            )));
        }
        let decimals = new.unit().1;
        let Some(entry) = request.rules.iter().rev().find(|entry| entry.index == index) else { continue };
        if let Some(per_call) = &entry.max_per_call {
            if !u256_equals(&new.max_amount, &base_units(per_call, decimals, "cap")?) {
                return Err(Error::plan(format!(
                    "The website's new plan does not have the per-call cap you asked for on rule {}.",
                    index + 1
                )));
            }
        }
        if let Some(per_day) = &entry.max_per_day {
            if !u256_equals(&new.max_daily, &base_units(per_day, decimals, "cap")?) {
                return Err(Error::plan(format!(
                    "The website's new plan does not have the per-day cap you asked for on rule {}.",
                    index + 1
                )));
            }
        }
    }
    Ok(())
}
