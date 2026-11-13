import type { Note } from "../machines";
import { t } from "../i18n";

/** The text of a status note ("%raw" carries a backend text as is). */
export function noteText(note: Note | null | undefined): string {
  if (!note) return "";
  if (note.key === "%raw") return String(note.params?.text ?? "");
  return t(note.key, note.params);
}

/** Show or hide an element. */
export function show(element: HTMLElement, visible: boolean): void {
  element.hidden = !visible;
}

/** A Unix time as "YYYY-MM-DD HH:MM:SS" in UTC and in local time. */
export function utcAndLocal(seconds: number): { utc: string; local: string } {
  const moment = new Date(seconds * 1000);
  const pad = (value: number) => String(value).padStart(2, "0");
  const utc = `${moment.getUTCFullYear()}-${pad(moment.getUTCMonth() + 1)}-${pad(moment.getUTCDate())} ${pad(moment.getUTCHours())}:${pad(moment.getUTCMinutes())}:${pad(moment.getUTCSeconds())}`;
  const local = `${moment.getFullYear()}-${pad(moment.getMonth() + 1)}-${pad(moment.getDate())} ${pad(moment.getHours())}:${pad(moment.getMinutes())}:${pad(moment.getSeconds())}`;
  return { utc, local };
}

/** Keep a log box's lines in sync (appends only new lines, scrolls to the end). */
export function syncLog(box: HTMLElement, lines: string[]): void {
  const shown = Number(box.dataset.count ?? "0");
  if (lines.length < shown) {
    box.textContent = "";
    box.dataset.count = "0";
    return syncLog(box, lines);
  }
  if (lines.length === shown) return;
  box.textContent += lines.slice(shown).map((line) => line + "\n").join("");
  box.dataset.count = String(lines.length);
  box.scrollTop = box.scrollHeight;
}
