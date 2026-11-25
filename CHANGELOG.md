# Changelog

## 0.7.0

The signer is renamed **Anubis Automation Script Signer** (formerly the
Awake Helix Signer). What it verifies and signs does not change.

- **It is a new app.** The app identifier is now
  `com.sivilization.anubisauto.signer` (was `com.sivilization.awakehelix.signer`):
  the Android package and the iOS / macOS bundle identifier change, so 0.7.0
  installs next to the old app instead of updating it, and nothing the old
  app or the old command line stored carries over (its app data, settings
  folder, paired browsers, remembered language and theme, link registration
  and terminal command). Set it up again: load your key, pair the dashboard,
  register links, install the terminal command; then uninstall the old app.
  Keystore files you saved yourself stay where they are, and grants on chain
  are unaffected: grants made with the old app are revoked from the new one.
- Links: everything the app and the command line make uses `anubisauto://`
  (`anubisauto://sign`, `://revoke`, `://grants`, `://ping`). The old
  `awakehelix://` links still open the app, so old links and QR codes keep
  working; both schemes are registered on every platform (Windows registry,
  Linux desktop file, macOS and iOS `Info.plist`, Android intent filter) and
  parsed alike. Any other scheme or look-alike is refused as before.
- Names: the command is `anubisauto-signer` (installer PATH, `.deb`
  `/usr/bin/anubisauto-signer`, `install-cli` symlink), the app binary
  `anubisauto-signer-app`, the desktop entry `anubisauto-signer.desktop`, the
  settings folder `AnubisAutoSigner` (Windows, macOS) or
  `~/.config/anubisauto-signer` (Linux), the HTTP User-Agent
  `anubisauto-signer/<version>` and the companion's `name`. Release files are
  `anubisauto-signer-<version>-<platform>…` (with `SHA256SUMS` and
  `manifest.json` naming them). The window title, the texts in all six
  languages, the install check ("… is installed and linked") and the
  summaries use the new name.
- Protocol: grant plans must name the schema `anubisauto-signer-plan/2`;
  revocation plans may name `anubisauto-signer-plan/1` or `/2`, or the former
  `awake-helix-signer-plan/1` or `/2`, so grants made with the old app can
  still be revoked. The session key attestation's EIP-712 domain name is
  "Anubis Automation Session Key Attestation" (version "1"); an attestation
  under the former name is refused. The website changes to match.
- Builds: the Docker images, volumes and BuildKit builder of `build.sh` /
  `build.ps1` are named `anubisauto-signer-*` (`clean` no longer sees the
  caches of earlier versions). The Android release keystore keeps its folder
  (`~/.awake-helix-signing/`); without `HELIX_ANDROID_KEY_ALIAS` its only key
  is used, and a release build checks that the APK is signed with that key's
  certificate. A `src-tauri/gen` Android or Xcode project generated for the
  former identifier is generated again.

## 0.6.0

- The pinned delegate is the version 2 Helix7702 Diamond
  `0xA37eBF54868c76B52A35741859d9835609d48695` (runtime code hash
  `0x59e8a793…64c9f2`, same EntryPoint). Its account facet is version 1 with
  the Origin rule kinds 10-26 appended; storage, structs and selectors are
  unchanged, so a wallet keeps its grants when it moves.
- Wallets on the version 1 Diamond (`0xdaFCb6c6…8ff56A`, still pinned with its
  code hash as `IMPLEMENTATION_V1`):
  - a new grant is one type-4 transaction that re-delegates the wallet to
    version 2 and installs the grant; the summary says "move the account from
    the version 1 to the version 2 Helix Diamond" and "Moves from: …";
  - a revocation is a plain self-call on version 1 (its code hash is checked)
    and leaves the delegation as it is.
  A plain wallet is delegated to version 2 (grants, and revocations of a
  dormant grant). After a grant the wallet must be on version 2; after a
  revocation on version 1 or 2.
- Grant plans must name the version 2 Diamond (naming version 1 is refused
  with its own message); revocation plans may name either, and must name the
  one the wallet uses. `--dev-constants` takes `implementationV1` and
  `implementationV1CodeHash`.
- Origin (origindefi) rules: New Turbo 2.5x / 4x / Community participate,
  activate, sell and stakeAgain; Community Distributor claim; Long Staking
  360 / 600 and Energy Staking stake, claimInterest, unstakePrincipal and
  turbineExtraInterest; Burn Fixed and Burn Bond claim / claimAll, Burn Bond
  depositDAI / depositLGNS, Energy Burner burn, Burn Bond Ranking Reward
  claimReward, Origin Turbine silence / redeemSilence, and their DAI / LGNS
  approvals. The allow-list is the version 1 list plus exactly the website's
  `ORIGIN_RULE_ALLOWLIST`. Each rule is checked like the contract: price
  floor and deadline (1 s to 1 hour) for participate, activate and sell,
  deadline only for silence, the activation DAI cap for activate, one call
  per call for the claim kinds (their daily cap counts calls), no token or
  counterparty.
- Method names repeat across kinds (participate 1/10, activate 5/11, claim
  14/18): the website's rule preview is matched by kind as well, messages
  name the kind ("participate (kind 10)"), and `--cap` accepts
  `method@kind` or `method@contract` (`claim@18=,4`).
- The summary (command line and app, six languages) shows units per kind
  (LGNS with 9 decimals, "at most N calls per UTC day" for the claim kinds),
  the Origin contract names, the floors ("at least 10 LGNS per 1 DAI",
  "at least 0.9 DAI back per 1 DAI paid", "at least 0.5 DAI per 1 LGNS"),
  the activation DAI cap of New Turbo activate, and that silence and
  redeemSilence always pay your own account. The app's editor names each
  rule with its contract and keeps a claim rule's per-call cap at 1.

## 0.5.4

- Website calls wait at most 10 s to connect and then 30 s for the answer
  (sign-in steps, the grant list, the revocation calls; logout 10 s), instead
  of one 30 s limit for the whole request. Every other HTTPS/JSON-RPC request
  also connects within 10 s and keeps its former answer timeout.
- A slow or overloaded website is told apart from one that cannot be reached:
  - "The website is busy and did not answer in time; try again in a moment"
    (`website.busy`) when the answer did not come in time after connecting,
    for HTTP 502/503/504, and for the website's new `server.busy` answer;
  - "Cannot reach the website; check the internet connection" (`website.unreachable`)
    for DNS failures, refused connections, connect timeouts and TLS failures.
  Both are translated in all six languages. A failed sign-in still says
  "Signing in to the website failed" (登入網站失敗…), now followed by the
  translated cause instead of an English "Cannot reach …: timed out". Other
  requests without an answer in time say so (`network.busy`), and the
  website's own `server.busy` text is translated where it shows.
- GET requests to the website (`/api/csrf`, `/api/grants`) are sent once more
  after a 1.5 s pause when the website was busy or a timeout hit. POST
  requests (sign-in challenge and verification, revocation call and
  confirmation) are never repeated.
- The grant list may come from the website's cached copy while it re-reads
  the chain (`refreshing`, with `generatedAt`): the app shows that list at
  once with a note "Updating the statuses from the chain…" and reads it again
  every 3 s, up to 5 times; the command line reads it again the same way
  before printing and says when statuses may be a few seconds old.
  Revocation does not depend on it: the revocation call is always read fresh.

## 0.5.3

- Typing AUTHORIZE / REVOKE in the app works with any input method: the word
  is compared after Unicode NFKC normalization (full-width letters such as
  ＡＵＴＨＯＲＩＺＥ from a Chinese/Japanese/Korean input method count as
  ASCII), ignoring case, spaces and invisible characters, in both the page
  and the app backend (`flow::confirm_word_matches`). Look-alike letters from
  other scripts are still refused. The command line keeps its exact prompt.
- An Enter that only commits an input method's composition (Zhuyin, Pinyin,
  kana…) no longer submits the word before it is in the field.
- Sign and Confirm are enabled once the typed word matches; a refused word
  stays in the field so it can be corrected instead of being cleared.

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
