import type { Msg, Summary } from "../api";
import { h } from "../dom";
import { getLanguage, msgParts, tParts, type Parts } from "../i18n";
import type { Note } from "../machines";
import { summaryLines } from "../summary";

/** A log line: a note (message key) or a verified summary. */
export type LogEntry = Note | { summary: Summary };

/** The note of a backend message. */
export function msgNote(msg: Msg, tone?: Note["tone"]): Note {
  return { key: "%msg", params: { msg }, tone };
}

/** The translated text of a status note and its untranslated details. */
export function noteParts(note: Note | null | undefined): Parts {
  if (!note) return { text: "", raw: [] };
  if (note.key === "%msg") return msgParts(note.params?.msg as Msg);
  return tParts(note.key, note.params);
}

/** The text of a status note (details appended). */
export function noteText(note: Note | null | undefined): string {
  const parts = noteParts(note);
  return [parts.text, ...parts.raw].filter(Boolean).join(" ");
}

/** Nodes of a translated text: the text, then each untranslated detail marked as raw data. */
export function partsNodes(parts: Parts): Node[] {
  return [
    document.createTextNode(parts.text),
    ...parts.raw.map((text) => h("span", { class: "raw", "data-raw": "", dir: "auto" }, text)),
  ];
}

/** Replace an element's content with a translated text and its details. */
export function showParts(element: HTMLElement, parts: Parts): void {
  element.replaceChildren(...partsNodes(parts));
}

/** Show or hide an element. */
export function show(element: HTMLElement, visible: boolean): void {
  element.hidden = !visible;
}

function entryLines(entry: LogEntry): HTMLElement[] {
  if ("summary" in entry) {
    return summaryLines(entry.summary).map((line) =>
      h("div", { class: `log-line indent-${line.indent}${line.warning ? " warning-inline" : ""}` }, partsNodes(line.parts)),
    );
  }
  return [h("div", { class: "log-line" }, partsNodes(noteParts(entry)))];
}

/** Keep a log box in sync: appends new entries, re-renders all of them after a language change. */
export function syncLog(box: HTMLElement, entries: readonly LogEntry[]): void {
  const shown = Number(box.dataset.count ?? "0");
  const language = getLanguage();
  if (entries.length < shown || box.dataset.language !== language) {
    box.replaceChildren();
    box.dataset.count = "0";
    box.dataset.language = language;
    if (entries.length) syncLog(box, entries);
    return;
  }
  if (entries.length === shown) return;
  box.append(...entries.slice(shown).flatMap(entryLines));
  box.dataset.count = String(entries.length);
  box.scrollTop = box.scrollHeight;
}

/** Render a verified summary into a box (one element per line). */
export function renderSummary(box: HTMLElement, summary: Summary | null): void {
  box.replaceChildren(
    ...(summary
      ? summaryLines(summary).map((line) =>
          h("div", { class: `summary-line indent-${line.indent}${line.warning ? " warning-inline" : ""}` }, partsNodes(line.parts)),
        )
      : []),
  );
}
