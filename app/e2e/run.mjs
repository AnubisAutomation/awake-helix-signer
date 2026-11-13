// End-to-end test of the built desktop app on Linux: the real binary (built
// with the dev-constants feature) in WebKitGTK under Xvfb, driven through
// tauri-driver + WebKitWebDriver (W3C WebDriver), against the fake website
// and chain of the signer test fakes (tests/py, served by
// e2e/fake_server.py).
//
//   1. The app starts with an awakehelix://sign link (as the OS would start
//      it): load a private key, verify the summary, edit calls/caps/expiry,
//      apply (the website re-plans, the app re-verifies), type AUTHORIZE, sign.
//   2. A second instance is started with awakehelix://grants (a link clicked
//      while the app runs): single-instance hands it to the running window,
//      which opens My grants; sign in, list, revoke one, revoke all.
//   The fake server's state is checked after each part (transactions,
//   reports, customize requests, revoke confirmations). Screenshots go to
//   $E2E_OUT (default ./test-results).
//
// Usage: node e2e/run.mjs <app binary> <fakes python>   (run by build/scripts/test.sh)
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const [app, python] = process.argv.slice(2).map((item) => resolve(item));
if (!app || !python) throw new Error("usage: node e2e/run.mjs <app binary> <python with eth-account>");
const out = resolve(process.env.E2E_OUT || "test-results");
mkdirSync(out, { recursive: true });
const children = [];
const stop = () => children.forEach((child) => child.kill("SIGTERM"));
process.on("exit", stop);

function start(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
  children.push(child);
  child.stderr.on("data", (data) => process.env.E2E_VERBOSE && process.stderr.write(`[${command}] ${data}`));
  return child;
}

// ---------------------------------------------------------------- fake world
const configFile = join(out, "fake-config.json");
rmSync(configFile, { force: true }); // never read a previous run's config
start(python, ["-I", resolve("e2e/fake_server.py"), configFile]);
for (let i = 0; i < 300 && !existsSync(configFile); i++) await sleep(100);
await sleep(200); // the file is written in one call; give it a moment to be complete
const fake = JSON.parse(readFileSync(configFile, "utf8"));
const state = async () => (await fetch(`${fake.api}/__state`)).json();
console.log(`fake website + RPC at ${fake.api}`);

const env = {
  ...process.env,
  AWAKE_HELIX_SIGNER_DEV_CONSTANTS: fake.constants,
  AWAKE_HELIX_SIGNER_RPC: fake.rpc,
  AWAKE_HELIX_SIGNER_API: fake.api,
};

// ------------------------------------------------------------------ webdriver
const driverPort = 4444;
start("tauri-driver", ["--port", String(driverPort)], { env });
const base = `http://127.0.0.1:${driverPort}`;
async function wd(method, path, body) {
  const response = await fetch(base + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok || json.value?.error) throw new Error(`${method} ${path}: ${JSON.stringify(json.value ?? json)}`);
  return json.value;
}
for (let i = 0; i < 50; i++) {
  try {
    await fetch(`${base}/status`);
    break;
  } catch {
    await sleep(200);
  }
}
const signLink = `awakehelix://sign?plan=${fake.signToken}&api=${encodeURIComponent(fake.api)}`;
const session = await wd("POST", "/session", {
  capabilities: { alwaysMatch: { "tauri:options": { application: app, args: [signLink] } } },
});
const id = session.sessionId;
const s = (path) => `/session/${id}${path}`;

const ELEMENT = "element-6066-11e4-a52f-4a8a2e9e66b6";
async function find(testid, timeout = 20000) {
  const until = Date.now() + timeout;
  for (;;) {
    try {
      const found = await wd("POST", s("/element"), { using: "css selector", value: `[data-testid="${testid}"]` });
      const handle = found[ELEMENT] ?? Object.values(found)[0];
      if (!handle) throw new Error(`no element ${testid}`);
      return handle;
    } catch (error) {
      if (Date.now() > until) throw error;
      await sleep(200);
    }
  }
}
const text = async (testid) => wd("GET", s(`/element/${await find(testid)}/text`));
const click = async (testid) => wd("POST", s(`/element/${await find(testid)}/click`), {});
async function type(testid, value) {
  const element = await find(testid);
  await wd("POST", s(`/element/${element}/clear`), {});
  await wd("POST", s(`/element/${element}/value`), { text: value });
}
const script = (body, args = []) => wd("POST", s("/execute/sync"), { script: body, args });
async function waitFor(what, check, timeout = 60000) {
  const until = Date.now() + timeout;
  let last;
  for (;;) {
    try {
      last = await check();
      if (last) return last;
    } catch (error) {
      last = error.message;
    }
    if (Date.now() > until) {
      await shot(`timeout-${what.replace(/\W+/g, "-")}`);
      throw new Error(`timed out waiting for ${what} (last: ${String(last).slice(0, 400)})`);
    }
    await sleep(300);
  }
}
async function shot(name) {
  const png = await wd("GET", s("/screenshot"));
  writeFileSync(join(out, `${name}.png`), Buffer.from(png, "base64"));
}
const status = () => text("status");
function assert(condition, message) {
  if (!condition) throw new Error(`assertion failed: ${message}`);
  console.log(`  ok - ${message}`);
}

try {
  // ------------------------------------------------------------ 1. authorize
  console.log("1. awakehelix://sign link -> key -> summary -> edit -> authorize");
  await waitFor("the request page", async () => (await text("request-heading")) === "Authorize a hosted bot");
  assert((await text("site-line")).includes(fake.api), "the window names the link's website");
  assert((await text("site-line")).includes("NOT the official site"), "and warns it is not the official one");
  await click("key-source-privateKey");
  await type("key-private", fake.privateKey);
  await click("request-load");
  const summary = await waitFor("the verified summary", async () => {
    const value = await text("summary");
    return value.includes(fake.owner) && value;
  });
  assert(summary.includes("at most 256 bot operations"), "summary decoded from the calldata (256 calls)");
  assert((await script("return document.querySelector('[data-testid=key-private]').value")) === "", "the private key field was cleared");
  assert((await text("key-address")).includes(fake.owner), "the key box shows the loaded address");
  await shot("1-verified");

  await type("edit-calls", "200");
  await type("edit-call-0", "15");
  await type("edit-day-0", "30");
  await type("confirm-word", "AUTHORIZE");
  assert(!(await wd("GET", s(`/element/${await find("sign")}/enabled`))), "Sign is disabled while edits are not applied");
  await click("edit-apply");
  await waitFor("the re-verified summary", async () => (await text("summary")).includes("at most 200 bot operations"));
  assert((await text("summary")).includes("15 DAI per call"), "the new cap is in the verified summary");
  await shot("2-edited");
  await type("confirm-word", "AUTHORIZE");
  await click("sign");
  const result = await waitFor("the transaction", async () => {
    const value = await text("result");
    return value.startsWith("Done") && value;
  });
  assert(/block \d+/.test(result) && result.includes("The website was notified."), `signed and reported: ${result.slice(0, 90)}…`);
  await shot("3-signed");
  let world = await state();
  assert(world.sent.length === 1, "one transaction reached the chain");
  assert(world.reports.length === 1 && world.reports[0][0] === fake.signToken, "the website got the report");
  assert(world.customized.length === 1 && world.customized[0].remainingCalls === 200, "the website got the edit");
  assert((await script("return document.querySelector('[data-testid=key-panel] .key-form').hidden")) === false, "the key was wiped after signing");

  // ------------------------------------------------------------ 2. my grants
  console.log("2. second instance with awakehelix://grants -> sign in -> revoke one -> revoke all");
  const second = spawn(app, [`awakehelix://grants?api=${encodeURIComponent(fake.api)}`], { env, stdio: "ignore" });
  const code = await new Promise((done) => second.on("exit", done));
  assert(code === 0, "the second instance handed the link over and exited");
  await waitFor("the grants page", async () => (await script("return document.querySelector('[data-testid=tab-grants]').classList.contains('active')")) === true);
  await click("key-source-privateKey");
  await type("key-private", fake.privateKey);
  await click("grants-load");
  await waitFor("the grant list", async () => (await status()).includes("4 grant(s) on"));
  const rows = await script("return [...document.querySelectorAll('[data-testid=grant-row]')].map((row) => row.dataset.grant + ' ' + row.className)");
  assert(rows.length === 4, `four grants listed (${rows.map((row) => row.split(" ").pop()).join(", ")})`);
  await shot("4-grants");
  await click(`grant-select-${fake.grants[0]}`);
  await click("grants-revoke-selected");
  await waitFor("the verified revocation", async () => (await status()).includes("Type REVOKE"));
  await type("grants-word", "REVOKE");
  await click("grants-confirm");
  await waitFor("the revocation", async () => (await status()) === "Revoked 1 of 1 grant(s).");
  assert(
    (await script(`return document.querySelector('[data-grant="${fake.grants[0]}"]').className`)).includes("status-revoked"),
    "the revoked grant shows as revoked",
  );
  await click("grants-revoke-all");
  await waitFor("the verified revocations", async () => (await status()).includes("Type REVOKE"));
  await type("grants-word", "REVOKE");
  await click("grants-confirm");
  await waitFor("revoke all", async () => (await status()) === "Revoked 1 of 1 grant(s).");
  await shot("5-revoked");
  world = await state();
  assert(world.confirmations.length === 2, "the website confirmed both revocations");
  const left = world.policy[fake.owner.toLowerCase()] ?? [];
  assert(!left.includes(fake.grants[0]) && !left.includes(fake.grants[1]), "both active grants are gone from the chain");
  assert(left.includes(fake.grants[2]) && left.length === 2, "left on chain: the expired grant and the one authorized in part 1");

  // ------------------------------------------------------- 3. languages, theme
  await script("document.querySelector('[data-testid=language]').value = 'zh-Hant'; document.querySelector('[data-testid=language]').dispatchEvent(new Event('change'))");
  assert((await text("tab-grants")) === "我的授權", "language switch (zh-Hant)");
  await script("document.querySelector('[data-testid=theme]').value = 'dark'; document.querySelector('[data-testid=theme]').dispatchEvent(new Event('change'))");
  assert((await script("return document.documentElement.getAttribute('data-theme')")) === "dark", "theme switch (dark)");
  await shot("6-zh-Hant-dark");
  // Phone width: one column, the grant table becomes cards.
  await wd("POST", s("/window/rect"), { width: 390, height: 844 });
  await sleep(500);
  assert((await script("return document.documentElement.scrollWidth <= window.innerWidth + 1")) === true, "no horizontal scrolling at 390 px");
  await shot("7-phone-width-grants");
  await click("tab-request");
  await shot("8-phone-width-request");
  console.log("e2e ok");
} finally {
  await wd("DELETE", s("")).catch(() => undefined);
  stop();
}
process.exit(0);
