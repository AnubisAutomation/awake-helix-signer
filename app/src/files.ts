// File access through tauri-plugin-dialog and tauri-plugin-fs: a keystore is
// read from a file the user picked, and an encrypted keystore is written only
// where the user chose to save it. Nothing else touches the disk.

export interface PickedKeystore {
  /** Desktop: the path the backend reads. */
  path?: string;
  /** Mobile (content:// or sandboxed URIs): the file's text. */
  json?: string;
  name: string;
}

function baseName(path: string): string {
  const clean = decodeURIComponent(path.split("?")[0]);
  return clean.split(/[\\/]/).pop() || clean;
}

/** Let the user pick a keystore file; null when cancelled. */
export async function pickKeystore(mobile: boolean): Promise<PickedKeystore | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const chosen = await open({
    multiple: false,
    directory: false,
    title: "Keystore JSON",
    // Keystore files are often named UTC--…--address without an extension.
    filters: mobile ? undefined : [{ name: "Keystore", extensions: ["json", "*"] }],
  });
  if (!chosen || Array.isArray(chosen)) return null;
  const path = String(chosen);
  if (!mobile) return { path, name: baseName(path) };
  const { readTextFile } = await import("@tauri-apps/plugin-fs");
  return { json: await readTextFile(path), name: baseName(path) };
}

/** Ask where to save an encrypted keystore and write it; returns the path, or null when cancelled. */
export async function saveKeystore(json: string, address: string): Promise<string | null> {
  const [{ save }, { writeTextFile }] = await Promise.all([import("@tauri-apps/plugin-dialog"), import("@tauri-apps/plugin-fs")]);
  const stamp = new Date().toISOString().replace(/[:]/g, "-").replace(/\.\d+Z$/, ".0Z");
  const path = await save({
    title: "Encrypted keystore",
    defaultPath: `UTC--${stamp}--${address.toLowerCase().replace(/^0x/, "")}.json`,
    filters: [{ name: "Keystore", extensions: ["json"] }],
  });
  if (!path) return null;
  await writeTextFile(path, json);
  return path;
}
