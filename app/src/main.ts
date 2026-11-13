import "./style.css";
import { api } from "./api";
import { start, store } from "./app";
import { initLanguage } from "./i18n";
import { selftest } from "./selftest";
import { applyTheme, storedTheme } from "./theme";
import { Shell } from "./views/shell";

applyTheme(storedTheme());
initLanguage();
const root = document.getElementById("app")!;
const shell = new Shell();
root.replaceChildren(shell.root);

start()
  .then(async () => {
    if (store.info?.selftest) {
      const { ok, detail } = await selftest(shell);
      await api.selftestDone(ok, detail);
    }
  })
  .catch(async (error) => {
    const message = String(error?.message ?? error);
    root.append(Object.assign(document.createElement("pre"), { className: "fatal", textContent: message }));
    if (store.info?.selftest) await api.selftestDone(false, message).catch(() => undefined);
  });
