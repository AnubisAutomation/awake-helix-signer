// Make the generated Android project (src-tauri/gen/android, written by
// `tauri android init`) sign release builds with the keystore build.sh
// provides. The keystore and its password stay outside the repository; the
// Gradle build reads their paths from the environment:
//   HELIX_ANDROID_KEYSTORE                path of the .jks / PKCS12 keystore
//   HELIX_ANDROID_KEYSTORE_PASSWORD_FILE  file holding the store (= key) password
//   HELIX_ANDROID_KEY_ALIAS               key alias (build/scripts/android.sh reads it
//                                         from the keystore when it is not given)
// Idempotent: running it again leaves a patched file unchanged.
// Usage: node scripts/android-signing.mjs <gen/android dir>
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const MARK = "// anubisauto: release signing";
const dir = process.argv[2] ?? "src-tauri/gen/android";
const file = join(dir, "app", "build.gradle.kts");
let text = readFileSync(file, "utf8");

if (!text.includes(MARK)) {
  const block = /\n([ \t]*)buildTypes \{/.exec(text);
  if (!block) throw new Error(`${file}: no buildTypes block to patch`);
  const pad = block[1];
  const signing = [
    `${MARK} (keystore outside the repository, see build.sh)`,
    "signingConfigs {",
    '    create("release") {',
    '        val store = System.getenv("HELIX_ANDROID_KEYSTORE")',
    '        val passwordFile = System.getenv("HELIX_ANDROID_KEYSTORE_PASSWORD_FILE")',
    "        if (store != null && passwordFile != null) {",
    "            val secret = File(passwordFile).readText().trim()",
    "            storeFile = File(store)",
    "            storePassword = secret",
    "            keyPassword = secret",
    '            keyAlias = System.getenv("HELIX_ANDROID_KEY_ALIAS") ?: "anubisauto-signer"',
    '            storeType = "PKCS12"',
    "        }",
    "    }",
    "}",
  ].map((line) => pad + line).join("\n");
  text = text.replace(block[0], `\n${signing}\n${pad}buildTypes {`);
  const release = /getByName\("release"\) \{\n([ \t]*)/.exec(text);
  if (!release) throw new Error(`${file}: no release build type to patch`);
  text = text.replace(
    release[0],
    `${release[0]}if (System.getenv("HELIX_ANDROID_KEYSTORE") != null) signingConfig = signingConfigs.getByName("release")\n${release[1]}`,
  );
  // Inside android {} `java` names the Java extension, so import File at the top.
  if (!/^import java\.io\.File$/m.test(text)) text = `import java.io.File\n${text}`;
  writeFileSync(file, text);
  console.log(`patched ${file} for release signing`);
} else {
  console.log(`${file} already signs release builds`);
}
