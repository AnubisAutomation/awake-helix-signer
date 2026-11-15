# Changelog

## 0.5.2

- The app now shows everything in the selected language (繁體中文, 简体中文,
  English, 日本語, 한국어, Español), and switching the language re-renders
  what is already on screen:
  - the verified summary is rendered from the data the core decoded from the
    calldata, not from the command line's English text;
  - progress lines, refusals and errors of the core and the app backend carry
    a stable code with their values (`Message`, `msg!`), so the app translates
    them; a message without a code of its own shows a translated headline and
    its English text apart;
  - the website's error answers are shown by their code (`code`/`params`, sent
    by the website since this release), else in the website's own Chinese or
    English text, marked as untranslated;
  - the grants list (linked bot, counts, dates), the editor, dialogs, the file
    dialogs' titles, the window title and the header labels; dates and counts
    use the language's format.
- The editor's "Calls" field is now "Calls allowed" (可執行次數, 可执行次数,
  実行可能回数, 실행 가능 횟수, Operaciones permitidas) with a line explaining
  it: how many on-chain operations the bot may perform with the grant (one per
  rule a run touches); at 0 the grant stops working even before it expires.
  The grants list and the summary use the same words.
- The command line's output is unchanged (English).

## 0.5.1

- My grants (app), `grants list` and `grants revoke` (CLI) show the new grant
  statuses of the website: `inactive` (the grant is still stored, but the
  account is not delegated to Helix7702Account; it becomes active again if the
  account re-delegates), `missing` as "not installed", and `unavailable` only
  for a temporary chain read failure, with a retry hint. An unknown status is
  shown as it is, and Revoke is only offered when the website says the grant is
  revocable.
- Revoking a dormant grant of an account whose EIP-7702 delegation was cleared
  now works: the signer reads the grant from the account's storage, sends one
  type-4 transaction whose authorization (nonce + 1) re-delegates the account
  to the pinned implementation and revokes the grant, then verifies the
  delegation and the cleared key on chain. A grant under another contract's
  delegation is still refused, with an explanation.
- "Revoke all active" includes dormant (`inactive`) grants the signer can revoke.

## 0.5.0

- Initial open-source release.
