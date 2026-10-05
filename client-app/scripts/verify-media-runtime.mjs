import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(scriptDirectory, "..");
const tauriRoot = join(clientRoot, "src-tauri");
const runtime = join(tauriRoot, "bin", "runtime");
const config = JSON.parse(readFileSync(join(tauriRoot, "tauri.conf.json"), "utf8"));

if (config.bundle?.resources?.["bin/runtime"] !== "runtime") {
  throw new Error('Tauri must package "bin/runtime" as the installed "runtime" directory.');
}

for (const executable of ["ffmpeg.exe", "ffprobe.exe"]) {
  const path = join(runtime, executable);
  if (!existsSync(path)) {
    throw new Error(`Required packaged media tool is missing: ${path}`);
  }
  const result = spawnSync(path, ["-version"], {
    cwd: runtime,
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${executable} failed its runtime/DLL check: ${result.error?.message || result.stderr || `exit ${result.status}`}`);
  }
  console.log(`[MEDIA_RUNTIME] ${executable}: ${(result.stdout || "").split(/\r?\n/, 1)[0]}`);
}

console.log(`[MEDIA_RUNTIME] Tauri will recursively package ${runtime} as runtime/.`);
