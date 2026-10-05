import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "../../release/client-web/GUI/node_modules/playwright/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const appRoot = resolve(here, "../..");
const workspace = resolve(appRoot, "../..");
const sourceRoot = join(appRoot, "client-app/src-tauri/bin");
const installRoot = process.env.SENTINEL_TEST_INSTALL_DIR || sourceRoot;
const core = join(installRoot, "sentinelgate.exe");
const runtime = join(installRoot, "runtime");
const full256 = process.env.SENTINEL_LOCAL_256_E2E === "1";
const fixtureRoot = join(workspace, full256 ? ".build-target/protect-gui-flow-harness-256" : ".build-target/protect-gui-flow-harness");
const isolatedLocalAppData = full256 ? process.env.SENTINEL_E2E_LOCALAPPDATA : join(fixtureRoot, "isolated-localappdata");
if (full256) assert.ok(isolatedLocalAppData, "set SENTINEL_E2E_LOCALAPPDATA to an isolated test profile; refusing to touch the real Windows profile");
const localStorageRoot = full256 ? join(isolatedLocalAppData, "SentinelGate", "storage") : join(fixtureRoot, "local-storage");
const audio = full256 ? join(fixtureRoot, "carrier-normalized.wav") : join(workspace, "SentinelGate_CPP_SOURCE/sentinelgate/test.wav");
const input = join(fixtureRoot, "input file fixture.txt");
const outputDir = join(fixtureRoot, "protected fragments");
const password = "Sentinel-Harness-Only-2026!";
const jobId = "0123456789abcdef0123456789abcdef";

assert.ok(existsSync(core), `core binary missing: ${core}`);
assert.ok(existsSync(join(runtime, "libcrypto-4-x64.dll")), `runtime DLL missing: ${runtime}`);
rmSync(fixtureRoot, { recursive: true, force: true });
mkdirSync(outputDir, { recursive: true });
if (full256) {
  writeFileSync(input, Buffer.alloc(64 * 1024 * 1024, 0x5a));
  const sampleRate = 44100, durationSeconds = 1000, sampleCount = sampleRate * durationSeconds;
  const wav = Buffer.alloc(44 + sampleCount * 2);
  wav.write("RIFF", 0); wav.writeUInt32LE(wav.length - 8, 4); wav.write("WAVE", 8);
  wav.write("fmt ", 12); wav.writeUInt32LE(16, 16); wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22); wav.writeUInt32LE(sampleRate, 24); wav.writeUInt32LE(sampleRate * 2, 28);
  wav.writeUInt16LE(2, 32); wav.writeUInt16LE(16, 34); wav.write("data", 36); wav.writeUInt32LE(sampleCount * 2, 40);
  for (let beat = 0; beat * sampleRate / 2 < sampleCount; beat += 1) {
    const start = Math.round(beat * sampleRate / 2);
    for (let offset = 0; offset < 3200 && start + offset < sampleCount; offset += 1) {
      wav.writeInt16LE(Math.round(26000 * (1 - offset / 3200) * Math.sin(2 * Math.PI * 1000 * offset / sampleRate)), 44 + (start + offset) * 2);
    }
  }
  writeFileSync(audio, wav);
} else {
  writeFileSync(input, Buffer.from("SentinelGate GUI protect flow fixture with a local Windows path.\n", "utf8"));
}
const inputHash = createHash("sha256").update(readFileSync(input)).digest("hex");
assert.ok(existsSync(audio), `audio fixture missing: ${audio}`);
const fragmentPaths = [];
let coreResult;
let restoreCoreCalls = 0;
let protectTempCleanups = 0;
let restoreTempCleanups = 0;
let carrierTempCleanups = 0;
const tempCleanupPaths = [];
let signalRestoreTempCleanup;
const restoreTempCleanupSignal = new Promise(resolveCleanup => { signalRestoreTempCleanup = resolveCleanup; });

const calls = [];
const uploaded = new Map();
let createPayload;
let localManifest;
let localStorageAvailable = true;
let completedJob;
let finalized = false;
let rejectUploads = false;
let rejectLocalStorage = false;
let rejectLocalPermission = false;
let rejectCreates = false;
let rejectFinalizes = false;
let server;

function sendJson(res, status, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": bytes.length });
  res.end(bytes);
}

server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith("/api/")) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const route = `${req.method} ${url.pathname}`;
    calls.push({ method: req.method, route, authenticated: req.headers.authorization === "Bearer fixture-session-token", ngrokSkip: req.headers["ngrok-skip-browser-warning"] === "true", contentType: req.headers["content-type"] || "", bytes: body.length });
    if (route === "GET /api/health") return sendJson(res, 200, { status: "online", system: "SentinelGate Web API", engineStatus: "Ready" });
    if (req.headers.authorization !== "Bearer fixture-session-token") return sendJson(res, 401, { success: false, error: { code: "INVALID_SESSION", message: "Fixture auth missing." } });

    if (route === "GET /api/auth/session") return sendJson(res, 200, { user: { id: "fixture-user", username: "Harness" } });
    if (route === "POST /api/protection/client-jobs") {
      if (rejectCreates) return sendJson(res, 503, { success: false, error: { code: "JOB_STORE_UNAVAILABLE", message: "fixture client-job creation failure" } });
      createPayload = JSON.parse(body.toString("utf8"));
      assert.deepEqual(Object.keys(createPayload).sort(), ["files", "storageMode", "storageVersion"]);
      assert.equal(createPayload.storageMode, "local");
      assert.equal(createPayload.storageVersion, 1);
      assert.equal(createPayload.files.length, 1);
      assert.deepEqual(Object.keys(createPayload.files[0]).sort(), ["originalName", "sizeBytes"]);
      assert.equal(createPayload.files[0].originalName, "input file fixture.txt");
      assert.equal(createPayload.files[0].sizeBytes, statSync(input).size);
      return sendJson(res, 201, { success: true, jobId, status: "processing", storageMode: "local", storageVersion: 1 });
    }
    const uploadMatch = url.pathname.match(/^\/api\/protection\/client-jobs\/([a-f0-9]{32})\/files\/(\d+)\/fragments\/(\d+)$/);
    if (req.method === "PUT" && uploadMatch) {
      assert.equal(uploadMatch[1], jobId);
      const fileIndex = Number(uploadMatch[2]);
      const fragmentIndex = Number(uploadMatch[3]);
      assert.equal(fileIndex, 0, "backend fileIndex is array order and starts at zero");
      assert.equal(req.headers["content-type"], "application/octet-stream");
      assert.ok(body.length > 0);
      if (rejectUploads) return sendJson(res, 413, { success: false, error: { code: "LIMIT_FILE_SIZE", message: "fixture server rejected the encrypted fragment" } });
      uploaded.set(`${fileIndex}:${fragmentIndex}`, body);
      return sendJson(res, 201, { success: true, fragmentIndex, sizeBytes: body.length });
    }
    if (route === `POST /api/protection/client-jobs/${jobId}/complete`) {
      const metadata = JSON.parse(body.toString("utf8"));
      assert.equal(metadata.storageMode, "local");
      assert.equal(metadata.storageVersion, 1);
      assert.equal(metadata.files.length, 1);
      assert.equal(metadata.files[0].totalFragments, fragmentPaths.length);
      assert.match(metadata.files[0].sha256, /^[a-f0-9]{64}$/i);
      assert.equal(uploaded.size, 0, "local Protect must not upload encrypted fragments");
      if (rejectFinalizes) return sendJson(res, 500, { success: false, error: { code: "JOB_FINALIZE_FAILED", message: "fixture finalize body preserved" } });
      finalized = true;
      createPayload.resultFiles = metadata.files;
      completedJob = { id: jobId, status: "completed", storageMode: "local", storageVersion: 1, createdAt: new Date().toISOString(), completedAt: new Date().toISOString(), result: { files: metadata.files } };
      return sendJson(res, 200, { success: true, job: { ...completedJob, progress: 100 } });
    }
    if (route === `POST /api/protection/client-jobs/${jobId}/heartbeat`) return sendJson(res, 200, { success: true, heartbeatAt: new Date().toISOString() });
    if (route === `POST /api/protection/client-jobs/${jobId}/fail`) return sendJson(res, 200, { success: true });
    if (route === "POST /api/restore/client-jobs") return sendJson(res, 201, { success: true, job: { id: "restore-fixture-job", status: "completed", storageMode: "local" } });
    if (route === "GET /api/protection/jobs") return sendJson(res, 200, { success: true, jobs: completedJob ? [completedJob] : [] });
    return sendJson(res, 200, { success: true, jobs: [], entries: [], items: [], stats: {} });
  }

  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/") pathname = "/GUI/index.html";
  const file = normalize(join(appRoot, "release/client-web", pathname.replace(/^\//, "")));
  if (!file.startsWith(join(appRoot, "release/client-web")) || !existsSync(file) || !statSync(file).isFile()) {
    res.writeHead(404); return res.end("not found");
  }
  if (pathname === "/config.js") {
    res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
    return res.end(`window.SERVER_URL = "http://127.0.0.1:${server.address().port}";`);
  }
  const mime = extname(file) === ".html" ? "text/html; charset=utf-8" : extname(file) === ".js" ? "text/javascript; charset=utf-8" : extname(file) === ".css" ? "text/css" : extname(file) === ".svg" ? "image/svg+xml" : "application/octet-stream";
  res.writeHead(200, { "content-type": mime });
  createReadStream(file).pipe(res);
});

await new Promise(resolveListen => server.listen(0, "127.0.0.1", resolveListen));
const apiBase = `http://127.0.0.1:${server.address().port}/api`;
const browser = await chromium.launch({ channel: "msedge", headless: true });
try {
  const page = await browser.newPage();
  await page.exposeFunction("__runPackagedCoreProtect", args => {
    if (args.inputPath !== input || args.audioPath !== audio || args.password !== password) throw new Error("Protect invoke arguments did not match the GUI fixture.");
    rmSync(outputDir, { recursive: true, force: true });
    mkdirSync(outputDir, { recursive: true });
    const result = spawnSync(core, ["protect", args.inputPath, args.audioPath, outputDir], {
      cwd: installRoot,
      env: { ...process.env, PATH: `${runtime};${process.env.PATH || ""}` },
      input: `${args.password}\n`,
      encoding: "utf8",
      windowsHide: true
    });
    if (result.status !== 0) throw new Error(`LOCAL_CORE_EXIT: exit=${result.status}; stdout=${result.stdout}; stderr=${result.stderr}`);
    coreResult = JSON.parse(result.stdout);
    assert.equal(coreResult.status, "success");
    const names = readdirSync(outputDir).sort();
    fragmentPaths.splice(0, fragmentPaths.length, ...names.map(name => join(outputDir, name)));
    assert.equal(fragmentPaths.length, coreResult.fragments);
    return { sha256: coreResult.sha256, total_fragments: coreResult.fragments, fragment_paths: fragmentPaths, work_dir: outputDir };
  });
  await page.exposeFunction("__persistLocalProtectedJob", ({ jobId: id, ownerId, files }) => {
    if (rejectLocalStorage) throw new Error("LOCAL_STORAGE_DISK_FULL: fixture disk is full");
    if (rejectLocalPermission) throw new Error("LOCAL_STORAGE_PERMISSION: fixture access denied");
    assert.equal(id, jobId);
    const localJobRoot = join(localStorageRoot, id);
    rmSync(localJobRoot, { recursive: true, force: true });
    const manifestFiles = files.map(file => {
      const targetDir = join(localJobRoot, "files", String(file.index));
      mkdirSync(targetDir, { recursive: true });
      const fragments = file.fragmentPaths.map((source, index) => {
        const name = `fragment-${index}.bin`;
        copyFileSync(source, join(targetDir, name));
        return { index, name, sizeBytes: statSync(join(targetDir, name)).size };
      });
      return { index: file.index, originalName: file.originalName, sizeBytes: file.sizeBytes, totalFragments: file.totalFragments, sha256: file.sha256, fragments };
    });
    localManifest = { storageMode: "local", storageVersion: 1, jobId: id, ownerId, files: manifestFiles };
    mkdirSync(localJobRoot, { recursive: true });
    writeFileSync(join(localJobRoot, "manifest.json"), JSON.stringify(localManifest));
    return localManifest;
  });
  await page.exposeFunction("__restorePackagedCore", args => {
    restoreCoreCalls += 1;
    const outputDir = join(fixtureRoot, "restore-output");
    mkdirSync(outputDir, { recursive: true });
    const outputPath = join(outputDir, "restored-output.bin");
    const result = spawnSync(core, ["restore", args.fragmentDir, outputPath], {
      cwd: installRoot, env: { ...process.env, PATH: `${runtime};${process.env.PATH || ""}` },
      input: `${args.password}\n`, encoding: "utf8", windowsHide: true
    });
    if (result.status !== 0) throw new Error(`LOCAL_CORE_RESTORE: exit=${result.status}; stdout=${result.stdout}; stderr=${result.stderr}`);
    return { sha256: JSON.parse(result.stdout).sha256, output_path: outputPath, output_dir: outputDir };
  });
  await page.exposeFunction("__listLocalProtectedJobs", () => localManifest ? [{
    ...localManifest,
    localIntegrity: localManifest.files.every(file => file.fragments.every(fragment => {
      const fragmentPath = join(localStorageRoot, localManifest.jobId, "files", String(file.index), fragment.name);
      return existsSync(fragmentPath) && statSync(fragmentPath).size === fragment.sizeBytes;
    }))
  }] : []);
  await page.exposeFunction("__resolveLocalProtectedJob", args => {
    if (!localStorageAvailable) throw new Error("LOCAL_STORAGE_MISSING: fixture payload unavailable on this computer");
    if (args.ownerId !== "fixture-user") throw new Error("LOCAL_STORAGE_MANIFEST_CORRUPT: owner does not match this account");
    if (!localManifest || localManifest.jobId !== args.jobId || localManifest.files[args.fileIndex]?.sha256 !== args.expectedSha256) throw new Error("LOCAL_STORAGE_MISSING: fixture payload unavailable on this computer");
    const selected = localManifest.files[args.fileIndex];
    for (const fragment of selected.fragments) {
      const fragmentPath = join(localStorageRoot, args.jobId, "files", String(args.fileIndex), fragment.name);
      if (!existsSync(fragmentPath)) throw new Error(`LOCAL_STORAGE_FRAGMENT_MISSING: fragment ${fragment.index} is missing`);
      if (statSync(fragmentPath).size !== fragment.sizeBytes) throw new Error(`LOCAL_STORAGE_FRAGMENT_CORRUPT: fragment ${fragment.index} size mismatch`);
    }
    return join(localStorageRoot, args.jobId, "files", String(args.fileIndex));
  });
  await page.exposeFunction("__setLocalStorageAvailable", value => { localStorageAvailable = Boolean(value); });
  await page.exposeFunction("__markLocalJobInterrupted", () => {
    rejectFinalizes = false;
    if (completedJob) completedJob = { ...completedJob, status: "failed", progress: 0, error: { code: "CLIENT_INTERRUPTED" } };
  });
  await page.exposeFunction("__copyRestoredFixture", args => copyFileSync(args.sourcePath, args.destinationPath));
  await page.exposeFunction("__cleanupHarnessTemp", ({ path }) => {
    tempCleanupPaths.push(path);
    if (path === outputDir) { rmSync(outputDir, { recursive: true, force: true }); protectTempCleanups += 1; }
    if (full256 && path === audio) { rmSync(audio, { force: true }); carrierTempCleanups += 1; }
    if (path === join(fixtureRoot, "restore-output")) { rmSync(path, { recursive: true, force: true }); restoreTempCleanups += 1; signalRestoreTempCleanup(); }
  });
  const restoreOutput = join(fixtureRoot, "restored-gui.bin");
  await page.addInitScript(({ apiBase, input, audio, inputSize, restoreOutput }) => {
    localStorage.setItem("access_token", "fixture-session-token");
    window.__TAURI__ = {
      core: { invoke: async (command, args = {}) => {
        if (command === "selected_file_info") return [{ path: input, name: "input file fixture.txt", size: inputSize, last_modified: 0 }];
        if (command === "download_track_audio") {
          if (window.__sgExpiredTrack) throw new Error("TRACK_EXPIRED");
          return audio;
        }
        if (command === "protect_local_file") return window.__runPackagedCoreProtect(args);
        if (command === "persist_local_protected_job") return window.__persistLocalProtectedJob(args);
        if (command === "list_local_protected_jobs") return window.__listLocalProtectedJobs();
        if (command === "local_protected_job_directory") return window.__resolveLocalProtectedJob(args);
        if (command === "restore_local_fragments") return window.__restorePackagedCore(args);
        if (command === "copy_restored_file") return window.__copyRestoredFixture(args);
        if (command === "upload_fragment") {
          const bytes = await window.__sgHarnessReadFragment(args.fragmentPath);
          const response = await fetch(`${args.apiBase}/protection/client-jobs/${args.jobId}/files/${args.fileIndex}/fragments/${args.fragmentIndex}`, {
            method: "PUT", headers: { Authorization: `Bearer ${args.token}`, "Content-Type": "application/octet-stream", "ngrok-skip-browser-warning": "true" }, body: bytes
          });
          const responseBody = await response.text();
          if (!response.ok) throw new Error(`FRAGMENT_UPLOAD_HTTP: HTTP ${response.status}; response body: ${responseBody}`);
          return;
        }
        if (command === "remove_temp_path") {
          return window.__cleanupHarnessTemp(args);
        }
        throw new Error(`Harness has no Tauri command adapter for ${command}`);
      } },
      dialog: { open: async () => null, save: async () => restoreOutput }
    };
    window.__sgHarnessReadFragment = async path => {
      const response = await fetch(`/__fixture/read?path=${encodeURIComponent(path)}`);
      if (!response.ok) throw new Error(`Fixture fragment read failed: ${response.status}`);
      return response.arrayBuffer();
    };
  }, { apiBase, input, audio, inputSize: statSync(input).size, restoreOutput });

  // Serve protected fixture bytes from an internal endpoint so the browser-side
  // invoke adapter can send the same fragment bytes as the native command.
  const previous = server.listeners("request")[0];
  server.removeAllListeners("request");
  server.on("request", async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === "/__fixture/read") {
      const path = url.searchParams.get("path");
      if (!fragmentPaths.includes(path)) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      return createReadStream(path).pipe(res);
    }
    return previous(req, res);
  });

  // Override only the harness's local file bridge; the page still executes the
  // repository's api.js and app.js and calls beginProtection() itself.
  await page.addInitScript(() => {
    window.__sgHarnessReadFragment = async path => {
      const response = await fetch(`/__fixture/read?path=${encodeURIComponent(path)}`);
      if (!response.ok) throw new Error(`Fixture fragment read failed: ${response.status}`);
      return response.arrayBuffer();
    };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/GUI/index.html`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => window.SentinelGateApi && typeof beginProtection === "function");
  await page.waitForFunction(() => document.documentElement.dataset.startupState === "complete", { timeout: 15000 });
  await page.evaluate(async ({ input, audio, inputSize }) => {
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "fixture-track", title: "Fixture" };
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    protectionPage.dataset.mode = "selection";
    await beginProtection();
  }, { input, audio, inputSize: statSync(input).size });
  await page.waitForFunction(() => document.getElementById("processingComplete").classList.contains("hidden") === false || document.getElementById("processingError").classList.contains("hidden") === false, { timeout: full256 ? 180000 : 15000 });
  const result = await page.evaluate(() => ({
    completed: !document.getElementById("processingComplete").classList.contains("hidden"),
    error: document.getElementById("processingErrorMessage").textContent,
    progress: document.getElementById("processingTrack").getAttribute("aria-valuenow")
  }));
  assert.equal(result.completed, true, `GUI flow failed: ${result.error}`);
  assert.equal(result.progress, "100");
  assert.equal(finalized, true);
  if (full256) assert.equal(coreResult.fragments, 256, "64 MiB real core Protect should produce exactly 256 fragments");
  assert.equal(uploaded.size, 0, "local protected fragments are not uploaded");
  assert.ok(calls.some(call => call.route === "POST /api/protection/client-jobs"));
  assert.ok(calls.some(call => call.route === `POST /api/protection/client-jobs/${jobId}/complete`));
  assert.equal(calls.filter(call => call.method === "PUT").length, 0);
  assert.equal(statSync(join(localStorageRoot, jobId, "files", "0", "fragment-0.bin")).size, localManifest.files[0].fragments[0].sizeBytes);
  if (full256) {
    assert.equal(localManifest.files[0].fragments.length, 256, "local manifest must persist all 256 fragments");
    assert.equal(readdirSync(join(localStorageRoot, jobId, "files", "0")).filter(name => /^fragment-\d+\.bin$/.test(name)).length, 256);
    const metadataReadback = await page.evaluate(async () => (await window.SentinelGateApi.protectionJobs()).jobs);
    const readback = metadataReadback.find(job => job.id === jobId);
    assert.equal(readback.status, "completed");
    assert.equal(readback.storageMode, "local");
    assert.equal(readback.result.files[0].totalFragments, 256, "server readback must contain metadata only for all fragments");
  }
  assert.ok(calls.filter(call => call.route.includes("/api/protection/client-jobs")).every(call => call.ngrokSkip));
  const successfulFragmentIndexes = [...uploaded.keys()];

  await page.evaluate(async () => {
    await selectHomeSection("Bảo vệ dữ liệu");
    await setProtectionMode("restore");
    await renderRestoreFileList();
  });
  const restoreViewDebug = await page.evaluate(() => ({
    active: pages.home.dataset.activeSection,
    selectionHidden: protectionSelection.classList.contains("hidden"),
    processingHidden: protectionProcessing.classList.contains("hidden"),
    workflowHidden: restoreWorkflow.classList.contains("hidden"),
    list: restoreJobsList.innerText
  }));
  if (!restoreViewDebug.list.includes("input file fixture.txt")) throw new Error(`Local Restore item was not rendered: ${JSON.stringify(restoreViewDebug)}`);
  await page.locator(".restore-file-item").first().click();
  await page.locator("#restorePassword").fill(password);
  await page.locator("#startRestoreButton").click();
  await page.waitForFunction(() => !document.getElementById("processingComplete").classList.contains("hidden") || !document.getElementById("processingError").classList.contains("hidden"), { timeout: full256 ? 180000 : 15000 });
  const localRestoreResult = await page.evaluate(() => ({
    complete: !document.getElementById("processingComplete").classList.contains("hidden"),
    error: document.getElementById("processingErrorMessage").textContent
  }));
  assert.equal(localRestoreResult.complete, true, `Local Restore failed: ${localRestoreResult.error}`);
  assert.equal(createHash("sha256").update(readFileSync(join(fixtureRoot, "restored-gui.bin"))).digest("hex"), inputHash, "restored output hash must match original input hash");
  if (full256) {
    await Promise.race([restoreTempCleanupSignal, new Promise((_, reject) => setTimeout(() => reject(new Error("Restore temp cleanup was not invoked after successful output save")), 5000))]);
    assert.equal(restoreCoreCalls, 1);
    assert.equal(protectTempCleanups, 1, `successful Protect temp fragments should be cleaned after local commit; cleanup paths=${JSON.stringify(tempCleanupPaths)}`);
    assert.equal(carrierTempCleanups, 1, "downloaded carrier temp should be cleaned after successful Protect");
    assert.equal(existsSync(audio), false, "carrier temp file should not remain after successful Protect");
    assert.equal(restoreTempCleanups, 1, `successful Restore plaintext temp should be cleaned after output save; cleanup paths=${JSON.stringify(tempCleanupPaths)}`);
    const localFragmentDir = join(localStorageRoot, jobId, "files", "0");
    const orderedNames = readdirSync(localFragmentDir).filter(name => /^fragment-\d+\.bin$/.test(name))
      .map(name => ({ name, index: Number(name.match(/\d+/)[0]) })).sort((a, b) => a.index - b.index);
    assert.equal(orderedNames.length, 256);
    assert.deepEqual(orderedNames.map(item => item.index), Array.from({ length: 256 }, (_, index) => index), "fragment sequence must be complete and ordered by index");
    assert.equal(calls.filter(call => call.route.includes("/fragments/archive")).length, 0, "local Restore must never call archive");
    assert.equal(readdirSync(localFragmentDir).filter(name => /^fragment-\d+\.bin$/.test(name)).length, 256, "protected fragments must remain after Restore");
    const beforeMissingRestoreCalls = restoreCoreCalls;
    const missingPath = join(localFragmentDir, "fragment-132.bin");
    const missingBytes = readFileSync(missingPath);
    rmSync(missingPath);
    await page.evaluate(async () => { await setProtectionMode("restore"); await renderRestoreFileList(); });
    await page.locator(".restore-file-item").first().click();
    await page.locator("#restorePassword").fill(password);
    await page.locator("#startRestoreButton").click();
    await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
    assert.match(await page.locator("#processingErrorMessage").textContent(), /fragment 132 is missing/i);
    assert.equal(restoreCoreCalls, beforeMissingRestoreCalls, "missing fragment must fail before decrypt/merge starts");
    assert.equal(calls.filter(call => call.route.includes("/fragments/archive")).length, 0);
    writeFileSync(missingPath, missingBytes);
    assert.equal(readdirSync(localFragmentDir).filter(name => /^fragment-\d+\.bin$/.test(name)).length, 256, "restore the test fragment after the missing-fragment case");
  }
  assert.equal(calls.filter(call => call.route.includes("/fragments/archive")).length, 0, "local Restore must not call server archive");

  if (!full256) {
  const savedEncryptedFragment = join(localStorageRoot, jobId, "files", "0", "fragment-0.bin");
  const validEncryptedFragmentBytes = readFileSync(savedEncryptedFragment);
  const damagedEncryptedFragmentBytes = Buffer.from(validEncryptedFragmentBytes);
  damagedEncryptedFragmentBytes[0] ^= 1;
  writeFileSync(savedEncryptedFragment, damagedEncryptedFragmentBytes);
  await page.evaluate(async () => { await setProtectionMode("restore"); await renderRestoreFileList(); });
  await page.locator(".restore-file-item").first().click();
  await page.locator("#restorePassword").fill(password);
  await page.locator("#startRestoreButton").click();
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  assert.equal(await page.locator("#processingComplete").evaluate(el => !el.classList.contains("hidden")), false, "corrupt encrypted fragments must not complete Restore");
  writeFileSync(savedEncryptedFragment, validEncryptedFragmentBytes);

  await page.evaluate(async () => {
    await window.__setLocalStorageAvailable(false);
    await setProtectionMode("restore");
    await renderRestoreFileList();
  });
  await page.locator(".restore-file-item").first().click();
  await page.locator("#restorePassword").fill(password);
  await page.locator("#startRestoreButton").click();
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  assert.match(await page.locator("#processingErrorMessage").textContent(), /unavailable on this computer|missing/i, "a second computer without the local payload must report missing local data");
  assert.equal(calls.filter(call => call.route.includes("/fragments/archive")).length, 0, "missing local payload must not fall back to legacy archive");
  await page.evaluate(() => window.__setLocalStorageAvailable(true));

  // An expired track must return directly to music selection before local
  // protection or any client-job/fragment request is attempted.
  const protectionCallCountBeforeExpiredTrack = calls.filter(call => call.route.includes("/api/protection/client-jobs")).length;
  await page.evaluate(async ({ input, inputSize }) => {
    await selectHomeSection(document.getElementById("protectionPage").dataset.homeTab);
    await setProtectionMode("protect");
    window.__sgExpiredTrack = true;
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "expired-track", title: "Expired fixture" };
    selectedSongElement.textContent = "Expired fixture";
    selectedSongElement.classList.remove("hidden");
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    protectionPage.dataset.mode = "selection";
    await beginProtection();
  }, { input, inputSize: statSync(input).size });
  await page.waitForFunction(() => document.getElementById("musicSearchStatus").textContent === "Bài hát này đã hết hiệu lực. Vui lòng tìm và chọn lại bài khác.");
  const expiredTrackUi = await page.evaluate(() => ({
    message: document.getElementById("musicSearchStatus").textContent,
    selectionVisible: !document.getElementById("protectionSelection").classList.contains("hidden"),
    processingHidden: document.getElementById("protectionProcessing").classList.contains("hidden"),
    processingErrorHidden: document.getElementById("processingError").classList.contains("hidden"),
    selectedSongCleared: selectedSong === null && document.getElementById("selectedSong").classList.contains("hidden"),
    focusedControl: document.activeElement.id,
    mode: protectionPage.dataset.mode
  }));
  assert.equal(expiredTrackUi.message, "Bài hát này đã hết hiệu lực. Vui lòng tìm và chọn lại bài khác.");
  assert.equal(expiredTrackUi.selectionVisible, true);
  assert.equal(expiredTrackUi.processingHidden, true);
  assert.equal(expiredTrackUi.processingErrorHidden, true);
  assert.equal(expiredTrackUi.selectedSongCleared, true);
  assert.equal(expiredTrackUi.focusedControl, "musicSearchInput");
  assert.equal(expiredTrackUi.mode, "selection");
  assert.equal(calls.filter(call => call.route.includes("/api/protection/client-jobs")).length, protectionCallCountBeforeExpiredTrack,
    "expired audio must not create a client-job or upload fragments");
  await page.evaluate(() => { window.__sgExpiredTrack = false; });

  rejectLocalStorage = true;
  finalized = false;
  uploaded.clear();
  await page.evaluate(async ({ input, audio, inputSize }) => {
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "fixture-track", title: "Fixture" };
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    await beginProtection();
  }, { input, audio, inputSize: statSync(input).size });
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  const failedUploadMessage = await page.locator("#processingErrorMessage").textContent();
  assert.match(failedUploadMessage, /disk is full/);
  assert.equal(finalized, false, "client-job must not finalize after local storage fails");
  assert.ok(existsSync(outputDir) && readdirSync(outputDir).length > 0, "encrypted core output should remain available after local commit failure");

  rejectLocalStorage = false;
  rejectLocalPermission = true;
  finalized = false;
  await page.evaluate(async ({ input, audio, inputSize }) => {
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "fixture-track", title: "Fixture" };
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    await beginProtection();
  }, { input, audio, inputSize: statSync(input).size });
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  assert.match(await page.locator("#processingErrorMessage").textContent(), /access denied|permission/i);
  assert.equal(finalized, false, "client-job must not finalize when local storage is not writable");
  rejectLocalPermission = false;
  rejectCreates = true;
  uploaded.clear();
  await page.evaluate(async ({ input, inputSize }) => {
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "fixture-track", title: "Fixture" };
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    await beginProtection();
  }, { input, inputSize: statSync(input).size });
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  const failedCreateMessage = await page.locator("#processingErrorMessage").textContent();
  assert.match(failedCreateMessage, /HTTP 503/);
  assert.match(failedCreateMessage, /fixture client-job creation failure/);
  assert.equal(uploaded.size, 0, "local protected payload must never upload when metadata creation fails");

  rejectCreates = false;
  rejectFinalizes = true;
  finalized = false;
  uploaded.clear();
  await page.evaluate(async ({ input, inputSize }) => {
    selectedFiles = [{ path: input, name: "input file fixture.txt", size: inputSize, lastModified: 0 }];
    selectedSong = { id: "fixture-track", title: "Fixture" };
    protectionPassword.value = "Sentinel-Harness-Only-2026!";
    await beginProtection();
  }, { input, inputSize: statSync(input).size });
  await page.waitForFunction(() => !document.getElementById("processingError").classList.contains("hidden"), { timeout: 15000 });
  const failedFinalizeMessage = await page.locator("#processingErrorMessage").textContent();
  assert.match(failedFinalizeMessage, /HTTP 500/);
  assert.match(failedFinalizeMessage, /fixture finalize body preserved/);
  assert.equal(uploaded.size, 0);
  assert.equal(finalized, false);

  await page.evaluate(() => {
    const invoke = window.__TAURI__.core.invoke;
    window.__sgRestoreDownloadCalls = 0;
    window.__TAURI__.core.invoke = async (command, args) => {
      if (command === "download_fragments") window.__sgRestoreDownloadCalls += 1;
      return invoke(command, args);
    };
    return selectHomeSection("Trang chủ");
  });
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Trang chủ" && getTabView("Trang chủ").classList.contains("is-active"));
  await page.locator(".manage-account").click();
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Cài đặt" && getTabView("Cài đặt").classList.contains("is-active"));
  assert.equal(await page.locator("#settingsUsername").textContent(), "Harness", "account button should navigate to the current account view");

  await page.locator('.tool-nav-item[data-nav-target="Trang chủ"]').click();
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Trang chủ" && getTabView("Trang chủ").classList.contains("is-active"));
  await page.evaluate(() => {
    protectionMode = "restore";
    protectionPage.dataset.mode = "restore";
    selectedRestoreFile = { jobId: "old-restore-job", fileIndex: 0, name: "old.bin", totalFragments: 256, sha256: "a".repeat(64) };
    restoreEntriesCache = [{ jobId: "old-restore-job", fileIndex: 0 }];
    restorePassword.value = "old-password";
    protectionSelection.classList.add("hidden");
    protectionProcessing.classList.remove("hidden");
    renderProcessingState({ operation: "restore", stage: "complete", progress: 100, currentFile: "old.bin", currentFragment: 256, totalFragments: 256, message: "old restore complete" });
  });
  await page.locator(".feature-protect").click();
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Bảo vệ dữ liệu" && getTabView("Bảo vệ dữ liệu").classList.contains("is-active"));
  const freshProtectionState = await page.evaluate(() => ({
    mode: protectionPage.dataset.mode,
    operation: processingState.operation,
    stage: processingState.stage,
    progress: document.getElementById("processingTrack").getAttribute("aria-valuenow"),
    restorePassword: restorePassword.value,
    selectedRestoreFile,
    restoreEntries: restoreEntriesCache.length,
    selectionVisible: !protectionSelection.classList.contains("hidden"),
    processingHidden: protectionProcessing.classList.contains("hidden"),
    restoreDownloads: window.__sgRestoreDownloadCalls
  }));
  assert.deepEqual(freshProtectionState, {
    mode: "protect", operation: "protect", stage: "idle", progress: "0", restorePassword: "",
    selectedRestoreFile: null, restoreEntries: 0, selectionVisible: true, processingHidden: true, restoreDownloads: 0
  }, "Home -> Protection should clear a finished Restore without resuming it");
  await page.evaluate(async () => {
    localStorage.setItem("user", JSON.stringify({ id: "fixture-user" }));
    await window.__markLocalJobInterrupted();
    await reconcileLocalProtectionJobs();
  });
  assert.equal(completedJob.status, "completed", `a complete, verified local manifest should recover interrupted metadata only; calls=${JSON.stringify(calls.filter(call => call.route.includes("client-jobs")))}`);
  assert.equal(finalized, true, "local metadata recovery should finalize without rerunning Protect");
  await page.locator('.tool-nav-item[data-nav-target="Lịch sử"]').click();
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Lịch sử" && getTabView("Lịch sử").classList.contains("is-active"));
  await page.waitForFunction(() => historyEntriesCache.some(entry => entry.jobId === "0123456789abcdef0123456789abcdef"));
  assert.equal(await page.evaluate(() => historyEntriesCache.find(entry => entry.jobId === "0123456789abcdef0123456789abcdef")?.storageMode), "local", "History must identify local payload separately from metadata");
  await page.locator('.tool-nav-item[data-nav-target="Kho dữ liệu"]').click();
  await page.waitForFunction(() => pages.home.dataset.activeSection === "Kho dữ liệu" && getTabView("Kho dữ liệu").classList.contains("is-active"));
  await page.waitForFunction(() => vaultEntriesCache.some(entry => entry.jobId === "0123456789abcdef0123456789abcdef"));
  assert.equal(await page.evaluate(() => vaultEntriesCache.find(entry => entry.jobId === "0123456789abcdef0123456789abcdef")?.localAvailable), true, "Vault must match local inventory against server metadata");
  console.log(JSON.stringify({ result: "PASS", flow: "app.js beginProtection -> packaged core -> local storage commit -> metadata-only finalize", expiredTrack: { result: "PASS", ui: expiredTrackUi, noClientJobOrFragmentUpload: true }, protectionNavigation: { result: "PASS", account: "PASS", history: "PASS", vault: "PASS", freshProtectionState }, errorPropagation: "PASS (metadata create HTTP 503, local storage disk-full, metadata finalize HTTP 500)", serverFragmentUploads: uploaded.size, core: coreResult, fileIndex: 0, fragmentIndexes: successfulFragmentIndexes, calls }, null, 2));
  }

  if (full256) {
    console.log(JSON.stringify({ result: "PASS", flow: "GUI Protect local -> 256 durable fragments -> metadata readback -> local Restore -> HMAC/hash verify", inputBytes: statSync(input).size, inputSha256: inputHash, fragmentCount: coreResult.fragments, manifestFragmentCount: localManifest.files[0].fragments.length, metadataFragmentCount: completedJob.result.files[0].totalFragments, fragmentOrder: "0..255", protectedFragmentsRemain: 256, fragmentUploads: uploaded.size, archiveRequests: calls.filter(call => call.route.includes("/fragments/archive")).length, restoreCoreCalls, missingFragmentFailsBeforeCore: true, protectTempCleanups, carrierTempCleanups, restoreTempCleanups, localStorageRoot, outputSha256: createHash("sha256").update(readFileSync(join(fixtureRoot, "restored-gui.bin"))).digest("hex") }, null, 2));
  }
} finally {
  await browser.close();
  await new Promise(resolveClose => server.close(resolveClose));
}
