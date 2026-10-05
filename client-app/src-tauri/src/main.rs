#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[cfg(windows)]
fn core_cli_path(path: &Path) -> Result<String, String> {
    use std::{ffi::OsString, os::windows::ffi::{OsStrExt, OsStringExt}};

    #[link(name = "kernel32")]
    extern "system" {
        fn GetShortPathNameW(long_path: *const u16, short_path: *mut u16, buffer_len: u32) -> u32;
    }

    let short_name = |candidate: &Path| -> Option<OsString> {
        let mut wide_path: Vec<u16> = candidate.as_os_str().encode_wide().collect();
        wide_path.push(0);
        let mut short_path = vec![0u16; 32768];
        let length = unsafe { GetShortPathNameW(wide_path.as_ptr(), short_path.as_mut_ptr(), short_path.len() as u32) };
        if length == 0 || length as usize >= short_path.len() { return None; }
        Some(OsString::from_wide(&short_path[..length as usize]))
    };
    let resolved = short_name(path).or_else(|| {
        let parent = path.parent()?;
        let name = path.file_name()?;
        if !name.to_string_lossy().is_ascii() { return None; }
        Some(PathBuf::from(short_name(parent)?).join(name).into_os_string())
    }).ok_or_else(|| format!("LOCAL_CORE_PATH_ENCODING: Windows could not resolve a legacy-compatible path for {}", path.display()))?;
    let value = resolved.to_string_lossy().into_owned();
    if !value.is_ascii() {
        return Err(format!("LOCAL_CORE_PATH_ENCODING: Windows has no ASCII short-path alias for {}; enable 8.3 short names on the containing volume or move the file to a volume that provides one", path.display()));
    }
    Ok(value)
}

#[cfg(not(windows))]
fn core_cli_path(path: &Path) -> Result<String, String> {
    Ok(path.to_string_lossy().into_owned())
}

fn api_request_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("ngrok-skip-browser-warning"),
        reqwest::header::HeaderValue::from_static("true"),
    );
    headers
}

fn api_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .default_headers(api_request_headers())
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| format!("Cannot initialize API client: {e}"))
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    let parsed = reqwest::Url::parse(&url).map_err(|error| format!("Invalid profile URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("Only HTTP and HTTPS profile URLs can be opened externally.".to_string());
    }

    #[cfg(windows)]
    {
        use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::Path};

        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut c_void,
                operation: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show_command: i32,
            ) -> *mut c_void;
        }

        let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let target: Vec<u16> = Path::new(&url).as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let result = unsafe {
            ShellExecuteW(std::ptr::null_mut(), operation.as_ptr(), target.as_ptr(), std::ptr::null(), std::ptr::null(), 1)
        };
        if result as isize <= 32 {
            return Err(format!("Windows could not open the profile URL (ShellExecuteW={}).", result as isize));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        Err("Opening profile URLs is supported by the Windows client only.".to_string())
    }
}

fn protection_log(stage: &str, detail: &str) {
    let base = env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(env::temp_dir);
    let directory = base.join("SentinelGate").join("logs");
    let result = fs::create_dir_all(&directory).and_then(|_| {
        let mut file = fs::OpenOptions::new().create(true).append(true).open(directory.join("protection.log"))?;
        writeln!(file, "[{stage}] {detail}")
    });
    if result.is_err() { eprintln!("[{stage}] {detail}"); }
}

fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() { text.to_string() } else { text.replace(secret, "[REDACTED]") }
}

fn is_expired_track_response(status: reqwest::StatusCode, body: &str) -> bool {
    if status != reqwest::StatusCode::GONE { return false; }
    let Ok(payload) = serde_json::from_str::<Value>(body) else { return false; };
    payload.get("code").and_then(Value::as_str) == Some("TRACK_EXPIRED")
        || payload.get("error").and_then(|error| error.get("code")).and_then(Value::as_str) == Some("TRACK_EXPIRED")
}

fn validate_binary_content_type(headers: &reqwest::header::HeaderMap, allow_audio: bool) -> Result<(), String> {
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .ok_or_else(|| "Server response is missing a valid Content-Type.".to_string())?;
    let valid = content_type == "application/octet-stream"
        || (allow_audio && content_type.starts_with("audio/"));
    if !valid {
        return Err(format!("Unexpected server Content-Type: {content_type}."));
    }
    Ok(())
}

fn audio_signature(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 12 && (&bytes[..4] == b"RIFF" || &bytes[..4] == b"RF64") && &bytes[8..12] == b"WAVE" { return Some("wav"); }
    if bytes.starts_with(b"fLaC") { return Some("flac"); }
    if bytes.starts_with(b"OggS") { return Some("ogg"); }
    if bytes.starts_with(b"ID3") || bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] & 0xe0 == 0xe0 { return Some("mpeg"); }
    if bytes.len() >= 12 && &bytes[..4] == b"FORM" && (&bytes[8..12] == b"AIFF" || &bytes[8..12] == b"AIFC") { return Some("aiff"); }
    if bytes.starts_with(b".snd") { return Some("au"); }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" { return Some("mp4"); }
    None
}

fn validate_audio_file(path: &Path) -> Result<&'static str, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("AUDIO_FILE: cannot inspect downloaded audio {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.len() < 12 { return Err(format!("AUDIO_FILE: downloaded carrier is not a complete audio file ({} bytes).", metadata.len())); }
    let mut file = fs::File::open(path).map_err(|e| format!("AUDIO_FILE: cannot read downloaded audio {}: {e}", path.display()))?;
    let mut header = [0u8; 16];
    let count = file.read(&mut header).map_err(|e| format!("AUDIO_FILE: cannot read audio signature: {e}"))?;
    audio_signature(&header[..count]).ok_or_else(|| format!("AUDIO_FILE: downloaded response is not a recognized audio format ({} bytes; possible HTML/interstitial response).", metadata.len()))
}

fn resolve_media_tool(name: &str) -> Result<PathBuf, String> {
    let root = package_dir()?;
    let filename = format!("{name}.exe");
    for candidate in [root.join("runtime").join(&filename), root.join(&filename)] {
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|e| format!("AUDIO_CONVERTER_PATH: cannot resolve {}: {e}", candidate.display()));
        }
    }
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join(&filename);
            if candidate.is_file() {
                return candidate.canonicalize().map_err(|e| format!("AUDIO_CONVERTER_PATH: cannot resolve {}: {e}", candidate.display()));
            }
        }
    }
    Err(format!("AUDIO_CONVERTER_MISSING: {name}.exe was not found in {}\\runtime, beside Sentinel.exe, or on PATH", root.display()))
}

fn run_media_tool(executable: &Path, args: &[&str], stage: &str) -> Result<String, String> {
    let mut child = Command::new(executable)
        .args(args)
        .env("PATH", media_tool_path(executable)?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{stage}: could not start {}: {e}", executable.display()))?;
    let stdout = child.stdout.take().ok_or_else(|| format!("{stage}: stdout pipe unavailable"))?;
    let stderr = child.stderr.take().ok_or_else(|| format!("{stage}: stderr pipe unavailable"))?;
    let stdout_reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let result = std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout), &mut bytes); (bytes, result) });
    let stderr_reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let result = std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr), &mut bytes); (bytes, result) });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill(); let _ = child.wait();
                let _ = stdout_reader.join(); let _ = stderr_reader.join();
                return Err(format!("{stage}: {} timed out after 120 seconds", executable.display()));
            }
            Err(e) => {
                let _ = child.kill(); let _ = child.wait();
                let _ = stdout_reader.join(); let _ = stderr_reader.join();
                return Err(format!("{stage}: could not wait for {}: {e}", executable.display()));
            }
        }
    };
    let (stdout, stdout_result) = stdout_reader.join().map_err(|_| format!("{stage}: stdout reader failed"))?;
    let (stderr, stderr_result) = stderr_reader.join().map_err(|_| format!("{stage}: stderr reader failed"))?;
    stdout_result.map_err(|e| format!("{stage}: could not read stdout: {e}"))?;
    stderr_result.map_err(|e| format!("{stage}: could not read stderr: {e}"))?;
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    let stderr = String::from_utf8_lossy(&stderr).trim().to_owned();
    protection_log(stage, &format!("executable={} status={} stdout={} stderr={}", executable.display(), status, stdout.trim(), stderr));
    if !status.success() { return Err(format!("{stage}: {} exited with {status}: {stderr}", executable.display())); }
    Ok(stdout)
}

fn media_tool_path(executable: &Path) -> Result<std::ffi::OsString, String> {
    let root = package_dir()?;
    let runtime = root.join("runtime");
    let tool_directory = executable.parent().ok_or_else(|| format!("AUDIO_CONVERTER_PATH: {} has no parent directory", executable.display()))?;
    let mut paths = vec![tool_directory.to_path_buf(), runtime];
    if let Some(existing) = env::var_os("PATH") { paths.extend(env::split_paths(&existing)); }
    env::join_paths(paths).map_err(|e| format!("AUDIO_CONVERTER_PATH: invalid child PATH: {e}"))
}

fn probe_audio(path: &Path, ffprobe: &Path, stage: &str) -> Result<Value, String> {
    let path_text = path.to_string_lossy().into_owned();
    let stdout = run_media_tool(ffprobe, &[
        "-v", "error", "-show_entries", "format=format_name:stream=codec_type,codec_name,sample_rate,channels,bits_per_sample,bits_per_raw_sample",
        "-of", "json", &path_text,
    ], stage)?;
    let metadata: Value = serde_json::from_str(&stdout).map_err(|e| format!("{stage}: ffprobe JSON parse failed: {e}; output={stdout}"))?;
    if !metadata["streams"].as_array().is_some_and(|streams| streams.iter().any(|stream| stream["codec_type"] == "audio")) {
        return Err(format!("{stage}: ffprobe found no audio stream in {}", path.display()));
    }
    Ok(metadata)
}

fn validate_pcm_wav(path: &Path, ffprobe: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|e| format!("AUDIO_WAV_INVALID: cannot inspect {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.len() < 44 { return Err(format!("AUDIO_WAV_INVALID: WAV is empty or shorter than a PCM header ({} bytes)", metadata.len())); }
    let mut header = [0u8; 44];
    fs::File::open(path).and_then(|mut file| file.read_exact(&mut header)).map_err(|e| format!("AUDIO_WAV_INVALID: cannot read WAV header: {e}"))?;
    if !is_expected_pcm_wav_header(&header) {
        return Err("AUDIO_WAV_INVALID: expected RIFF/WAVE PCM format tag 1, mono, 44100 Hz, 16-bit PCM.".into());
    }
    let probed = probe_audio(path, ffprobe, "AUDIO_WAV_FFPROBE")?;
    let stream = probed["streams"].as_array().and_then(|items| items.iter().find(|item| item["codec_type"] == "audio"))
        .ok_or_else(|| "AUDIO_WAV_INVALID: ffprobe found no audio stream.".to_string())?;
    let format = probed["format"]["format_name"].as_str().unwrap_or("");
    if !format.split(',').any(|name| name == "wav") || stream["codec_name"] != "pcm_s16le"
        || stream["sample_rate"].as_str() != Some("44100") || stream["channels"] != 1
        || !(stream["bits_per_sample"] == 16 || stream["bits_per_raw_sample"].as_str() == Some("16"))
    {
        return Err(format!("AUDIO_WAV_INVALID: ffprobe metadata does not match mono 44100 Hz PCM s16le WAV: {}", probed));
    }
    Ok(())
}

fn is_expected_pcm_wav_header(header: &[u8; 44]) -> bool {
    &header[0..4] == b"RIFF" && &header[8..12] == b"WAVE" && &header[12..16] == b"fmt "
        && u32::from_le_bytes(header[16..20].try_into().unwrap()) == 16
        && u16::from_le_bytes(header[20..22].try_into().unwrap()) == 1
        && u16::from_le_bytes(header[22..24].try_into().unwrap()) == 1
        && u32::from_le_bytes(header[24..28].try_into().unwrap()) == 44100
        && u16::from_le_bytes(header[34..36].try_into().unwrap()) == 16
}

fn normalize_audio_for_core(source: &Path) -> Result<(PathBuf, PathBuf), String> {
    let source_format = validate_audio_file(source)?;
    let ffmpeg = resolve_media_tool("ffmpeg")?;
    let ffprobe = resolve_media_tool("ffprobe")?;
    let source_info = probe_audio(source, &ffprobe, "AUDIO_SOURCE_FFPROBE")?;
    protection_log("AUDIO_SOURCE_FORMAT", &format!("path={} metadata={source_info}", source.display()));
    let dir = temp_job_dir("audio-normalized")?;
    let output = dir.join("carrier-normalized.wav");
    let source_text = source.to_string_lossy().into_owned();
    let output_text = output.to_string_lossy().into_owned();
    let conversion = run_media_tool(&ffmpeg, &[
        "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", &source_text,
        "-map", "0:a:0", "-vn", "-map_metadata", "-1", "-ac", "1", "-ar", "44100",
        "-c:a", "pcm_s16le", "-f", "wav", &output_text,
    ], "AUDIO_CONVERT")
    .map_err(|e| format!("AUDIO_CONVERT_FAILED: {e}"));
    if let Err(error) = conversion { protection_log("AUDIO_CONVERT_FAILED", &format!("source={} output={} error={error}", source.display(), output.display())); return Err(error); }
    validate_pcm_wav(&output, &ffprobe).map_err(|e| {
        let error = format!("AUDIO_WAV_INVALID: {e}; output={}", output.display());
        protection_log("AUDIO_WAV_INVALID", &error);
        error
    })?;
    protection_log("AUDIO_NORMALIZE_COMPLETE", &format!("source={} source_format={} output={} bytes={}", source.display(), source_format, output.display(), fs::metadata(&output).map(|m| m.len()).unwrap_or_default()));
    Ok((output, dir))
}

#[derive(Serialize)]
struct FileInfo {
    path: String,
    name: String,
    size: u64,
    last_modified: u128,
}

#[derive(Serialize)]
struct ProtectResult {
    sha256: String,
    total_fragments: usize,
    fragment_paths: Vec<String>,
    work_dir: String,
}

#[derive(Serialize)]
struct RestoreResult {
    sha256: String,
    output_path: String,
    output_dir: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FragmentArchiveManifest {
    success: bool,
    job_id: String,
    file_index: usize,
    sha256: String,
    fragments: Vec<FragmentArchiveEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FragmentArchiveEntry {
    index: usize,
    name: String,
    size_bytes: u64,
}

#[derive(Serialize)]
struct DownloadFragmentsResult {
    directory: String,
    total_fragments: usize,
}

fn package_dir() -> Result<PathBuf, String> {
    env::current_exe().map_err(|e| format!("Cannot resolve Sentinel.exe location: {e}"))?
        .parent().map(Path::to_path_buf).ok_or_else(|| "Sentinel.exe has no parent directory".into())
}

fn temp_job_dir(kind: &str) -> Result<PathBuf, String> {
    if kind == "audio" || kind == "audio-normalized" { prune_stale_audio_temp_dirs(); }
    let dir = env::temp_dir().join("SentinelGate").join(kind).join(Uuid::new_v4().to_string());
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create temporary work directory: {e}"))?;
    Ok(dir)
}

fn local_storage_root() -> Result<PathBuf, String> {
    let base = env::var_os("LOCALAPPDATA").map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is unavailable; cannot locate protected storage".to_string())?;
    Ok(base.join("SentinelGate").join("storage"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalProtectedFile {
    index: usize,
    original_name: String,
    size_bytes: u64,
    sha256: String,
    total_fragments: usize,
    fragment_paths: Vec<String>,
}

#[tauri::command]
fn persist_local_protected_job(job_id: String, owner_id: String, files: Vec<LocalProtectedFile>) -> Result<Value, String> {
    let root = local_storage_root()?;
    persist_local_protected_job_at(&root, &job_id, &owner_id, &files)
}

fn persist_local_protected_job_at(root: &Path, job_id: &str, owner_id: &str, files: &[LocalProtectedFile]) -> Result<Value, String> {
    if !is_valid_job_id(job_id) || owner_id.is_empty() || files.is_empty() || files.len() > 10 {
        return Err("LOCAL_STORAGE_INVALID_JOB: invalid job id or file list".into());
    }
    fs::create_dir_all(&root).map_err(|e| format!("LOCAL_STORAGE_PERMISSION: cannot create storage: {e}"))?;
    let job_dir = root.join(&job_id);
    fs::create_dir(&job_dir).map_err(|e| format!("LOCAL_STORAGE_CREATE: cannot create job directory: {e}"))?;
    let result = (|| -> Result<Value, String> {
        let mut manifest_files = Vec::with_capacity(files.len());
        for (expected_index, file) in files.iter().enumerate() {
            if file.index != expected_index || file.total_fragments == 0 || file.total_fragments != file.fragment_paths.len() || file.total_fragments > 256 || !is_valid_sha256(&file.sha256) {
                return Err(format!("LOCAL_STORAGE_MANIFEST: invalid metadata for file {}", file.index));
            }
            let directory = job_dir.join("files").join(file.index.to_string());
            fs::create_dir_all(&directory).map_err(|e| local_disk_error("LOCAL_STORAGE_PERMISSION", e))?;
            let mut fragments = Vec::with_capacity(file.fragment_paths.len());
            for (index, source) in file.fragment_paths.iter().enumerate() {
                let source = PathBuf::from(source);
                let name = format!("fragment-{index}.bin");
                let partial = directory.join(format!(".{name}.partial"));
                let target = directory.join(&name);
                fs::copy(&source, &partial).map_err(|e| local_disk_error("LOCAL_STORAGE_COPY", e))?;
                let source_size = fs::metadata(&source).map_err(|e| e.to_string())?.len();
                let copied_size = fs::metadata(&partial).map_err(|e| e.to_string())?.len();
                if source_size == 0 || source_size != copied_size {
                    let _ = fs::remove_file(&partial);
                    return Err(format!("LOCAL_STORAGE_VERIFY: fragment {index} size mismatch"));
                }
                fs::rename(&partial, &target).map_err(|e| local_disk_error("LOCAL_STORAGE_RENAME", e))?;
                fragments.push(serde_json::json!({"index": index, "name": name, "sizeBytes": copied_size}));
            }
            manifest_files.push(serde_json::json!({
                "index": file.index, "originalName": file.original_name,
                "sizeBytes": file.size_bytes, "totalFragments": file.total_fragments,
                "sha256": file.sha256.to_lowercase(), "fragments": fragments
            }));
        }
        let manifest = serde_json::json!({
            "storageMode": "local", "storageVersion": 1, "jobId": job_id, "ownerId": owner_id,
            "files": manifest_files, "createdAt": chrono_like_now()
        });
        let temporary = job_dir.join("manifest.json.partial");
        fs::write(&temporary, serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?)
            .map_err(|e| local_disk_error("LOCAL_STORAGE_MANIFEST_WRITE", e))?;
        fs::rename(&temporary, job_dir.join("manifest.json"))
            .map_err(|e| local_disk_error("LOCAL_STORAGE_MANIFEST_RENAME", e))?;
        Ok(manifest)
    })();
    if result.is_err() {
        // Leave partial job data in place for recovery; never silently discard protected fragments.
    }
    result
}

fn is_valid_job_id(value: &str) -> bool { value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()) }
fn is_valid_sha256(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) }
fn local_disk_error(prefix: &str, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied { format!("{prefix}_PERMISSION: {error}") }
    else if error.raw_os_error() == Some(112) { format!("LOCAL_STORAGE_DISK_FULL: {error}") }
    else { format!("{prefix}: {error}") }
}
fn chrono_like_now() -> String {
    // Timestamp is informational; avoid adding a time dependency to the desktop client.
    format!("unix:{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
}

#[tauri::command]
fn local_protected_job_directory(job_id: String, owner_id: String, file_index: usize, expected_sha256: String) -> Result<String, String> {
    let job_dir = local_storage_root()?.join(&job_id);
    resolve_local_protected_job_directory(&job_dir, &job_id, &owner_id, file_index, &expected_sha256)
}

fn resolve_local_protected_job_directory(job_dir: &Path, job_id: &str, owner_id: &str, file_index: usize, expected_sha256: &str) -> Result<String, String> {
    if !is_valid_job_id(&job_id) || !is_valid_sha256(&expected_sha256) { return Err("LOCAL_STORAGE_INVALID_JOB: invalid job metadata".into()); }
    let manifest_path = job_dir.join("manifest.json");
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).map_err(|_| "LOCAL_STORAGE_MISSING: protected data or manifest is missing on this computer".to_string())?)
        .map_err(|_| "LOCAL_STORAGE_MANIFEST_CORRUPT: local manifest cannot be read".to_string())?;
    if manifest["jobId"].as_str() != Some(job_id) || manifest["ownerId"].as_str() != Some(owner_id) || manifest["storageMode"].as_str() != Some("local") || manifest["storageVersion"].as_u64() != Some(1) {
        return Err("LOCAL_STORAGE_MANIFEST_CORRUPT: manifest identity or version is invalid".into());
    }
    let file = manifest["files"].as_array().and_then(|files| files.iter().find(|f| f["index"].as_u64() == Some(file_index as u64)))
        .ok_or_else(|| "LOCAL_STORAGE_FILE_MISSING: file is not present in local manifest".to_string())?;
    if !file["sha256"].as_str().unwrap_or_default().eq_ignore_ascii_case(&expected_sha256) {
        return Err("LOCAL_STORAGE_METADATA_MISMATCH: local manifest does not match server metadata".into());
    }
    let fragments = file["fragments"].as_array().ok_or_else(|| "LOCAL_STORAGE_MANIFEST_CORRUPT: fragment list is missing".to_string())?;
    if fragments.is_empty() || fragments.len() != file["totalFragments"].as_u64().unwrap_or_default() as usize {
        return Err("LOCAL_STORAGE_MANIFEST_CORRUPT: fragment count is invalid".into());
    }
    let fragment_dir = job_dir.join("files").join(file_index.to_string());
    for (i, fragment) in fragments.iter().enumerate() {
        let name = fragment["name"].as_str().unwrap_or_default();
        let expected_name = format!("fragment-{i}.bin");
        if name != expected_name { return Err("LOCAL_STORAGE_MANIFEST_CORRUPT: fragment sequence is invalid".into()); }
        let path = fragment_dir.join(name);
        let metadata = fs::metadata(&path).map_err(|_| format!("LOCAL_STORAGE_FRAGMENT_MISSING: fragment {i} is missing"))?;
        if metadata.len() != fragment["sizeBytes"].as_u64().unwrap_or_default() { return Err(format!("LOCAL_STORAGE_FRAGMENT_CORRUPT: fragment {i} size mismatch")); }
    }
    Ok(fragment_dir.to_string_lossy().into_owned())
}

#[tauri::command]
fn list_local_protected_jobs() -> Result<Vec<Value>, String> {
    let root = local_storage_root()?;
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(local_disk_error("LOCAL_STORAGE_READ", error)),
    };
    let mut manifests = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) { continue; }
        let Ok(bytes) = fs::read(entry.path().join("manifest.json")) else { continue; };
        let Ok(manifest) = serde_json::from_slice::<Value>(&bytes) else { continue; };
        if manifest["storageMode"] == "local" && manifest["storageVersion"] == 1 && manifest["jobId"].as_str() == entry.file_name().to_str() {
            let mut local_manifest = manifest;
            let mut integrity_ok = true;
            if let Some(files) = local_manifest["files"].as_array() {
                for file in files {
                    let Some(index) = file["index"].as_u64() else { integrity_ok = false; break; };
                    let Some(fragments) = file["fragments"].as_array() else { integrity_ok = false; break; };
                    if fragments.is_empty() || fragments.len() != file["totalFragments"].as_u64().unwrap_or_default() as usize { integrity_ok = false; break; }
                    for (fragment_index, fragment) in fragments.iter().enumerate() {
                        let expected_name = format!("fragment-{fragment_index}.bin");
                        if fragment["name"].as_str() != Some(expected_name.as_str()) { integrity_ok = false; break; }
                        let path = entry.path().join("files").join(index.to_string()).join(&expected_name);
                        if fs::metadata(path).map(|meta| meta.len()).ok() != fragment["sizeBytes"].as_u64() { integrity_ok = false; break; }
                    }
                    if !integrity_ok { break; }
                }
            } else { integrity_ok = false; }
            local_manifest["localIntegrity"] = Value::Bool(integrity_ok);
            manifests.push(local_manifest);
        }
    }
    Ok(manifests)
}

fn prune_stale_audio_temp_dirs() {
    let base = env::temp_dir().join("SentinelGate");
    let Some(expiry) = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(7 * 24 * 60 * 60)) else { return; };
    for kind in ["audio", "audio-normalized"] {
        let directory = base.join(kind);
        let Ok(entries) = fs::read_dir(&directory) else { continue; };
        for entry in entries.flatten() {
            let path = entry.path();
            let stale = entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry.metadata().ok().and_then(|meta| meta.modified().ok()).is_some_and(|modified| modified < expiry);
            if stale {
                match fs::remove_dir_all(&path) {
                    Ok(()) => protection_log("AUDIO_TEMP_PRUNED", &format!("path={} age_limit_days=7", path.display())),
                    Err(error) => protection_log("AUDIO_TEMP_PRUNE_ERROR", &format!("path={} error={error}", path.display())),
                }
            }
        }
    }
}

fn prune_stale_restore_output_dirs() {
    let directory = env::temp_dir().join("SentinelGate").join("output");
    let Some(expiry) = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(7 * 24 * 60 * 60)) else { return; };
    prune_stale_directories(&directory, expiry, "RESTORE_TEMP_PRUNED", "RESTORE_TEMP_PRUNE_ERROR");
}

fn prune_stale_protection_temp_dirs() {
    let directory = env::temp_dir().join("SentinelGate").join("protect");
    let Some(expiry) = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(7 * 24 * 60 * 60)) else { return; };
    prune_stale_directories(&directory, expiry, "PROTECT_TEMP_PRUNED", "PROTECT_TEMP_PRUNE_ERROR");
}

fn prune_stale_directories(directory: &Path, expiry: std::time::SystemTime, success_event: &str, error_event: &str) {
    let Ok(entries) = fs::read_dir(directory) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry.file_type().is_ok_and(|kind| kind.is_dir())
            && entry.metadata().ok().and_then(|meta| meta.modified().ok()).is_some_and(|modified| modified < expiry);
        if stale {
            match fs::remove_dir_all(&path) {
                Ok(()) => protection_log(success_event, &format!("path={} ", path.display())),
                Err(error) => protection_log(error_event, &format!("path={} error={error}", path.display())),
            }
        }
    }
}

fn run_core(mode: &str, args: &[&str], password: &str) -> Result<Value, String> {
    let root = package_dir()?;
    let executable = root.join("sentinelgate.exe");
    let runtime = root.join("runtime");
    if mode == "protect" {
        let audio_arg = args.get(1).ok_or_else(|| "LOCAL_CORE_AUDIO_FORMAT_ERROR: protect is missing its carrier audio argument".to_string())?;
        let audio_path = Path::new(audio_arg);
        protection_log("AUDIO", &format!("core_input={}", audio_path.display()));
        let validated_audio_path = fs::canonicalize(audio_path).unwrap_or_else(|_| audio_path.to_path_buf());
        if validated_audio_path.file_name() != Some(std::ffi::OsStr::new("carrier-normalized.wav")) {
            return Err(format!("LOCAL_CORE_AUDIO_FORMAT_ERROR: refusing to start C++ with {}; expected carrier-normalized.wav", audio_path.display()));
        }
        if !validated_audio_path.is_file() {
            return Err(format!("AUDIO_WAV_INVALID: normalized core input does not exist: {}", validated_audio_path.display()));
        }
        let ffprobe = resolve_media_tool("ffprobe")?;
        validate_pcm_wav(&validated_audio_path, &ffprobe)?;
        protection_log("AUDIO", &format!("core_input_verified={}", audio_path.display()));
    }
    protection_log("LOCAL_CORE_RESOLVE", &format!(
        "mode={mode} executable={} runtime={}", executable.display(), runtime.display()
    ));
    if !executable.is_file() {
        protection_log("LOCAL_CORE_SPAWN_ERROR", &format!(
            "resolved_executable={} resolved_runtime={} error=sidecar_missing",
            executable.display(), runtime.display()
        ));
        return Err(format!("The bundled C++ core is missing: {}", executable.display()));
    }
    let mut paths = vec![runtime.clone()];
    if let Some(existing) = env::var_os("PATH") { paths.extend(env::split_paths(&existing)); }
    let joined = env::join_paths(paths).map_err(|e| format!("Invalid runtime path: {e}"))?;
    protection_log("LOCAL_CORE_START", &format!(
        "mode={mode} executable={} runtime={} cwd={} args={args:?}", executable.display(), runtime.display(), root.display()
    ));
    let mut child = Command::new(&executable)
        .current_dir(&root)
        .env("PATH", joined)
        .arg(mode)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().map_err(|e| {
            protection_log("LOCAL_CORE_SPAWN_ERROR", &format!(
                "mode={mode} executable={} runtime={} error={e}", executable.display(), runtime.display()
            ));
            format!("LOCAL_CORE_SPAWN: {mode}: unable to start local C++ core at {} (runtime {}): {e}", executable.display(), runtime.display())
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(error) = stdin.write_all(password.as_bytes()).and_then(|_| stdin.write_all(b"\n")) {
            protection_log("LOCAL_CORE_STDIN_ERROR", &format!("mode={mode} executable={} error={error}", executable.display()));
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("LOCAL_CORE_STDIN: {mode}: cannot send password to C++ core: {error}"));
        }
    }
    let stdout = child.stdout.take().ok_or_else(|| format!("{mode}: C++ stdout pipe unavailable"))?;
    let stderr = child.stderr.take().ok_or_else(|| format!("{mode}: C++ stderr pipe unavailable"))?;
    let stdout_reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let result = std::io::BufReader::new(stdout).read_to_end(&mut bytes); (bytes, result) });
    let stderr_reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let result = std::io::BufReader::new(stderr).read_to_end(&mut bytes); (bytes, result) });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30 * 60);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(100)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                protection_log("LOCAL_CORE_EXIT", &format!("mode={mode} result=timeout"));
                return Err(format!("{mode}: local C++ core timed out after 1800 seconds"));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                protection_log("LOCAL_CORE_EXIT", &format!("mode={mode} wait_error={error}"));
                return Err(format!("{mode}: cannot wait for local C++ core: {error}"));
            }
        }
    };
    let (stdout, stdout_read) = stdout_reader.join().map_err(|_| format!("{mode}: C++ stdout reader failed"))?;
    let (stderr, stderr_read) = stderr_reader.join().map_err(|_| format!("{mode}: C++ stderr reader failed"))?;
    let stdout_text = redact_secret(&String::from_utf8_lossy(&stdout), password);
    let stderr_text = redact_secret(&String::from_utf8_lossy(&stderr), password);
    protection_log("LOCAL_CORE_STDOUT", &format!("mode={mode} bytes={} content={}", stdout.len(), stdout_text.trim_end()));
    protection_log("LOCAL_CORE_EXIT", &format!(
        "mode={mode} executable={} runtime={} code={:?} stderr={}",
        executable.display(), runtime.display(), status.code(), stderr_text.trim()
    ));
    if !status.success() {
        let message = serde_json::from_str::<Value>(stderr_text.trim()).ok()
            .and_then(|value| value["message"].as_str().map(str::to_owned));
        if stderr_text.to_ascii_lowercase().contains("source_wavread") || stderr_text.to_ascii_lowercase().contains("riff header") {
            return Err(format!("LOCAL_CORE_AUDIO_FORMAT_ERROR: {mode}: core rejected normalized WAV; exit={status}; stderr={}", stderr_text.trim()));
        }
        return Err(format!("LOCAL_CORE_EXIT: {mode}: local C++ core exited with {status}{}", message
            .map(|value| format!(": {value}"))
            .or_else(|| (!stderr_text.trim().is_empty()).then(|| format!(": {}", stderr_text.trim())))
            .unwrap_or_default()));
    }
    stdout_read.map_err(|e| format!("{mode}: cannot read C++ stdout: {e}"))?;
    stderr_read.map_err(|e| format!("{mode}: cannot read C++ stderr: {e}"))?;
    protection_log("LOCAL_CORE_JSON", &format!("mode={mode} stdout_bytes={}", stdout.len()));
    let result: Value = serde_json::from_slice(&stdout).map_err(|e| {
        format!("LOCAL_CORE_JSON: {mode}: C++ exited successfully but stdout was invalid JSON: {e}; see LOCAL_CORE_STDOUT log ({} bytes)", stdout.len())
    })?;
    if result["status"] != "success" {
        return Err(format!("LOCAL_CORE_RESULT: {mode}: {}", result["message"].as_str().unwrap_or("local C++ core reported failure")));
    }
    Ok(result)
}

#[tauri::command]
fn selected_file_info(paths: Vec<String>) -> Result<Vec<FileInfo>, String> {
    paths.into_iter().map(|path| {
        let file = PathBuf::from(&path);
        let meta = fs::metadata(&file).map_err(|e| format!("Cannot read selected file: {e}"))?;
        if !meta.is_file() { return Err("A selected path is not a regular file.".into()); }
        let name = file.file_name().map(|v| v.to_string_lossy().into_owned()).ok_or("Invalid selected filename")?;
        Ok(FileInfo { path, name, size: meta.len(), last_modified: meta.modified().ok().and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok()).map(|v| v.as_millis()).unwrap_or_default() })
    }).collect()
}

#[tauri::command]
async fn download_track_audio(api_base: String, token: String, track_id: String) -> Result<String, String> {
    if track_id.is_empty() || !track_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { return Err("Invalid music track identifier.".into()); }
    let authorization_present = !token.trim().is_empty();
    protection_log("AUDIO", &format!("Authorization header present={authorization_present}"));
    if !authorization_present { return Err("AUDIO_DOWNLOAD_AUTH: access token is missing; sign in again.".into()); }
    let url = format!("{}/music/tracks/{}/audio", api_base.trim_end_matches('/'), track_id);
    let client = api_http_client()?;
    protection_log("AUDIO_DOWNLOAD_START", &format!("track_id={track_id} url={url}"));
    let response = client.get(url.clone()).bearer_auth(&token).send().await.map_err(|e| {
        protection_log("AUDIO_DOWNLOAD_ERROR", &format!("track_id={track_id} authorization_header_present=true request_error={e}"));
        format!("AUDIO_DOWNLOAD_NETWORK: cannot download carrier audio: {e}")
    })?;
    if !response.status().is_success() {
        let status = response.status();
        let content_type = response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();
        let ngrok_warning = response.headers().get("ngrok-error-code").and_then(|h| h.to_str().ok()).map(|v| format!(" ngrok returned {v}." )).unwrap_or_default();
        let body = redact_secret(&response.text().await.unwrap_or_default(), &token);
        protection_log("AUDIO_DOWNLOAD_ERROR", &format!("track_id={track_id} status={status} content_type={content_type}{ngrok_warning} body={body}"));
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("AUDIO_DOWNLOAD_AUTH: carrier audio request returned HTTP 401 Unauthorized. Response: {body}"));
        }
        if is_expired_track_response(status, &body) {
            protection_log("AUDIO_DOWNLOAD_TRACK_EXPIRED", &format!("track_id={track_id} status={status}"));
            return Err("TRACK_EXPIRED".into());
        }
        return Err(format!("AUDIO_DOWNLOAD_HTTP: carrier audio request returned HTTP {status} ({content_type}).{ngrok_warning} Response: {body}"));
    }
    if let Err(error) = validate_binary_content_type(response.headers(), true) {
        protection_log("AUDIO_DOWNLOAD_ERROR", &format!("track_id={track_id} content_type_error={error}"));
        return Err(format!("AUDIO_DOWNLOAD_CONTENT_TYPE: {error} HTML/ngrok interstitial responses are not valid carrier audio."));
    }
    let dir = temp_job_dir("audio")?;
    let path = dir.join("carrier-audio.bin");
    let download_result = async {
        let mut file = File::create(&path).await.map_err(|e| format!("AUDIO_DOWNLOAD_IO: cannot create temporary carrier file: {e}"))?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| format!("AUDIO_DOWNLOAD_IO: carrier audio transfer failed: {e}"))?;
            file.write_all(&bytes).await.map_err(|e| format!("AUDIO_DOWNLOAD_IO: cannot write carrier audio: {e}"))?;
        }
        file.flush().await.map_err(|e| format!("AUDIO_DOWNLOAD_IO: cannot flush carrier audio: {e}"))?;
        Ok::<(), String>(())
    }.await;
    if let Err(error) = download_result { let _ = fs::remove_dir_all(&dir); return Err(error); }
    let path_for_check = path.clone();
    let audio_format = match tokio::task::spawn_blocking(move || validate_audio_file(&path_for_check)).await {
        Ok(Ok(format)) => format,
        Ok(Err(error)) => { let _ = fs::remove_dir_all(&dir); protection_log("AUDIO_DOWNLOAD_ERROR", &error); return Err(error); }
        Err(error) => { let _ = fs::remove_dir_all(&dir); return Err(format!("AUDIO_DOWNLOAD_VALIDATION: audio validator failed: {error}")); }
    };
    let size = fs::metadata(&path).map(|m| m.len()).unwrap_or_default();
    protection_log("AUDIO_DOWNLOAD_COMPLETE", &format!("track_id={track_id} format={audio_format} bytes={size} path={}", path.display()));
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
async fn protect_local_file(input_path: String, audio_path: String, password: String) -> Result<ProtectResult, String> {
    protection_log("PROTECTION_START", "local protection command received");
    let result = tokio::task::spawn_blocking(move || protect_local_file_blocking(input_path, audio_path, password))
        .await.map_err(|e| format!("protect: local worker failed: {e}"))?;
    match &result {
        Ok(value) => protection_log("PROTECTION_LOCAL_COMPLETE", &format!("sha256={} fragments={}", value.sha256, value.total_fragments)),
        Err(error) => protection_log("PROTECTION_ERROR", &format!("stage=local_protect error={error}")),
    }
    result
}

fn protect_local_file_blocking(input_path: String, audio_path: String, password: String) -> Result<ProtectResult, String> {
    let input = PathBuf::from(&input_path);
    let input_meta = fs::metadata(&input).map_err(|e| format!("PROTECT_INPUT: cannot inspect input file {}: {e}", input.display()))?;
    if !input_meta.is_file() { return Err(format!("PROTECT_INPUT: selected input is not a regular file: {}", input.display())); }
    let _input_handle = fs::File::open(&input).map_err(|e| format!("PROTECT_INPUT: cannot read input file {}: {e}", input.display()))?;
    if input_meta.len() == 0 { return Err("PROTECT_INPUT: selected input file is empty.".into()); }
    let audio_source = PathBuf::from(&audio_path);
    let audio_format = validate_audio_file(&audio_source)?;
    protection_log("AUDIO", &format!("source={} source_format={audio_format}", audio_source.display()));
    protection_log("PROTECTION_INPUT_VALIDATED", &format!("input={} bytes={} audio_source={} source_format={audio_format}", input.display(), input_meta.len(), audio_source.display()));
    let (normalized_audio, normalized_dir) = normalize_audio_for_core(&audio_source)?;
    protection_log("AUDIO", &format!("normalized={}", normalized_audio.display()));
    protection_log("PROTECTION_AUDIO_READY", &format!("source={} normalized_wav={}", audio_source.display(), normalized_audio.display()));
    let dir = temp_job_dir("protect")?;
    let probe = dir.join(".write-test");
    if let Err(error) = fs::write(&probe, b"ok").and_then(|_| fs::remove_file(&probe)) {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!("PROTECT_OUTPUT: cannot prepare output directory {}: {error}", dir.display()));
    }
    protection_log("PROTECTION_OUTPUT_READY", &format!("directory={}", dir.display()));
    let dir_text = dir.to_string_lossy().into_owned();
    let normalized_text = normalized_audio.to_string_lossy().into_owned();
    let core_input = Path::new(&normalized_text);
    let ffprobe = resolve_media_tool("ffprobe")?;
    validate_pcm_wav(core_input, &ffprobe)?;
    protection_log("AUDIO", &format!("core_input={}", core_input.display()));
    let absolute_input = fs::canonicalize(&input)
        .map_err(|e| format!("PROTECT_INPUT: cannot resolve selected file {}: {e}", input.display()))?;
    let final_input_meta = fs::metadata(&absolute_input)
        .map_err(|e| format!("PROTECT_INPUT: cannot inspect selected file immediately before C++ launch {}: {e}", absolute_input.display()))?;
    protection_log("PROTECTION_INPUT_PRE_CORE", &format!(
        "gui_input={input_path:?} absolute_input={} exists={} regular_file={} bytes={}",
        absolute_input.display(), absolute_input.exists(), final_input_meta.is_file(), final_input_meta.len()
    ));
    let core_input_path = core_cli_path(&absolute_input)?;
    let core_audio_path = core_cli_path(&fs::canonicalize(&normalized_audio).map_err(|e| format!("AUDIO: cannot resolve normalized carrier path: {e}"))?)?;
    let core_output_path = core_cli_path(&fs::canonicalize(&dir).map_err(|e| format!("PROTECT_OUTPUT: cannot resolve output directory: {e}"))?)?;
    protection_log("PROTECTION_INPUT_CORE_PATH", &format!("absolute_input={} core_input={core_input_path:?}", absolute_input.display()));
    let result = match run_core("protect", &[&core_input_path, &core_audio_path, &core_output_path], &password) {
        Ok(result) => result,
        Err(error) => { let _ = fs::remove_dir_all(&dir); return Err(error); }
    };
    if let Err(error) = fs::remove_dir_all(&normalized_dir) {
        protection_log("AUDIO_NORMALIZE_CLEANUP_ERROR", &format!("path={} error={error}", normalized_dir.display()));
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir).map_err(|e| e.to_string())?.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    let total_fragments = result["fragments"].as_u64().ok_or("protect: C++ core omitted fragment count")? as usize;
    if total_fragments == 0 || paths.len() != total_fragments {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!("protect: C++ reported {total_fragments} fragments but {} fragment files were found", paths.len()));
    }
    Ok(ProtectResult {
        sha256: result["sha256"].as_str().ok_or("C++ core omitted SHA-256")?.to_string(),
        total_fragments,
        fragment_paths: paths.into_iter().map(|p| p.to_string_lossy().into_owned()).collect(),
        work_dir: dir_text,
    })
}

#[tauri::command]
async fn upload_fragment(api_base: String, token: String, job_id: String, file_index: usize, fragment_index: usize, fragment_path: String) -> Result<(), String> {
    let url = format!("{}/protection/client-jobs/{}/files/{}/fragments/{}", api_base.trim_end_matches('/'), job_id, file_index, fragment_index);
    let client = api_http_client()?;
    let metadata = tokio::fs::metadata(&fragment_path).await.map_err(|e| format!("FRAGMENT_UPLOAD_LOCAL: cannot inspect fragment {fragment_path}: {e}"))?;
    if !metadata.is_file() || metadata.len() == 0 { return Err(format!("FRAGMENT_UPLOAD_LOCAL: fragment is missing, not a file, or empty: {fragment_path}")); }
    protection_log("FRAGMENT_UPLOAD_START", &format!("url={url} file_index={file_index} fragment_index={fragment_index} bytes={}", metadata.len()));
    let mut previous_attempt_may_have_committed = false;
    for attempt in 1..=6 {
        let file = File::open(&fragment_path).await.map_err(|e| format!("Cannot open encrypted fragment: {e}"))?;
        let size = file.metadata().await.map_err(|e| e.to_string())?.len();
        let stream = ReaderStream::with_capacity(file, 64 * 1024);
        let body = reqwest::Body::wrap_stream(stream);
        let response = client.put(&url).bearer_auth(&token).header(reqwest::header::CONTENT_TYPE, "application/octet-stream").header(reqwest::header::CONTENT_LENGTH, size).body(body).send().await;
        match response {
            Ok(response) => {
                let status = response.status();
                let content_type = response.headers().get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()).unwrap_or("unknown").to_string();
                let body = redact_secret(&response.text().await.unwrap_or_else(|error| format!("<failed to read response body: {error}>")), &token);
                if status.is_success() {
                    let payload: Value = serde_json::from_str(&body).map_err(|error| format!("FRAGMENT_UPLOAD_RESPONSE: HTTP {status} {content_type}; invalid JSON body ({error}): {body}"))?;
                    if content_type.split(';').next().unwrap_or("").trim() != "application/json"
                        || payload["success"] != true
                        || payload["fragmentIndex"].as_u64() != Some(fragment_index as u64)
                        || payload["sizeBytes"].as_u64().filter(|size| *size > 0).is_none()
                    {
                        protection_log("FRAGMENT_UPLOAD_ERROR", &format!("url={url} attempt={attempt} status={status} content_type={content_type} body={body}"));
                        return Err(format!("FRAGMENT_UPLOAD_RESPONSE: HTTP {status} {content_type}; unexpected response body: {body}"));
                    }
                    protection_log("FRAGMENT_UPLOAD_RESULT", &format!("file_index={file_index} fragment_index={fragment_index} status={status} size_bytes={} body={body}", payload["sizeBytes"]));
                    return Ok(());
                }
                if status == reqwest::StatusCode::CONFLICT && previous_attempt_may_have_committed {
                    let payload: Value = serde_json::from_str(&body).unwrap_or_default();
                    if payload["error"]["code"] == "DUPLICATE_FRAGMENT" { return Ok(()); }
                    return Err(format!("FRAGMENT_UPLOAD_HTTP: HTTP {status}; response body: {body}"));
                }
                if (status.as_u16() == 429 || status.is_server_error()) && attempt < 4 {
                    previous_attempt_may_have_committed = true;
                    protection_log("FRAGMENT_UPLOAD_RETRY", &format!("url={url} attempt={attempt} status={status} body={body}"));
                    tokio::time::sleep(std::time::Duration::from_millis(if status.as_u16() == 429 { 2000 * attempt as u64 } else { 500 * attempt as u64 })).await;
                    continue;
                }
                protection_log("FRAGMENT_UPLOAD_ERROR", &format!("url={url} attempt={attempt} status={status} body={body}"));
                return Err(format!("FRAGMENT_UPLOAD_HTTP: HTTP {status}; response body: {body}"));
            }
            Err(error) if attempt < 4 && (error.is_connect() || error.is_timeout()) => {
                previous_attempt_may_have_committed = true;
                protection_log("FRAGMENT_UPLOAD_RETRY", &format!("url={url} attempt={attempt} network_error={error}"));
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
            }
            Err(error) => { protection_log("FRAGMENT_UPLOAD_ERROR", &format!("url={url} attempt={attempt} network_error={error}")); return Err(format!("FRAGMENT_UPLOAD_NETWORK: {error}")); }
        }
    }
    Err("Fragment upload exhausted its retry limit.".into())
}

#[tauri::command]
async fn download_fragments(api_base: String, token: String, job_id: String, file_index: usize, expected_sha256: String) -> Result<DownloadFragmentsResult, String> {
    let client = api_http_client()?;
    let base = api_base.trim_end_matches('/');
    let url = format!("{base}/protection/client-jobs/{job_id}/files/{file_index}/fragments/archive");
    let response = get_archive_with_retry(&client, &url, &token).await?;
    validate_binary_content_type(response.headers(), false)?;
    if response.headers().get("X-SentinelGate-Archive").and_then(|value| value.to_str().ok()) != Some("SGFRAG1") {
        return Err("Fragment archive is missing the SGFRAG1 format header.".into());
    }

    let expected_sha = expected_sha256.to_ascii_lowercase();
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Selected protected file has invalid SHA-256 metadata.".into());
    }
    let mut archive = FragmentArchiveReader::new(response);
    let header = archive.read_exact(12).await?;
    if &header[..8] != b"SGFRAG1\n" {
        return Err("Fragment archive has an invalid SGFRAG1 signature.".into());
    }
    let manifest_length = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    if manifest_length == 0 || manifest_length > 1024 * 1024 {
        return Err("Fragment archive manifest has an invalid size.".into());
    }
    let manifest_bytes = archive.read_exact(manifest_length).await?;
    let manifest: FragmentArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Fragment archive manifest is invalid: {error}"))?;
    if !manifest.success || manifest.job_id != job_id || manifest.file_index != file_index {
        return Err("Fragment archive metadata does not match the requested protected file.".into());
    }
    if manifest.sha256.to_ascii_lowercase() != expected_sha {
        return Err("Protected file SHA-256 metadata does not match the selected history entry.".into());
    }
    let total_fragments = manifest.fragments.len();
    if total_fragments == 0 || total_fragments > 256 {
        return Err("Protected file has an invalid fragment count.".into());
    }
    for (expected_index, fragment) in manifest.fragments.iter().enumerate() {
        if fragment.index != expected_index || fragment.name.is_empty()
            || fragment.name.contains('/') || fragment.name.contains('\\') || fragment.size_bytes == 0
        {
            return Err("Fragment archive manifest is incomplete, unsafe, or out of order.".into());
        }
    }
    let dir = temp_job_dir("restore")?;
    let download_result = async {
        for fragment in &manifest.fragments {
            let destination = dir.join(format!("fragment-{}.bin", fragment.index));
            let mut file = File::create(&destination).await
                .map_err(|error| format!("Cannot create temporary fragment file: {error}"))?;
            archive.copy_exact(fragment.size_bytes, &mut file).await?;
            file.flush().await.map_err(|error| format!("Cannot flush temporary fragment file: {error}"))?;
        }
        archive.ensure_finished().await?;
        Ok::<(), String>(())
    }.await;
    if let Err(error) = download_result {
        let _ = fs::remove_dir_all(&dir);
        protection_log("PROTECTION_ERROR", &format!("stage=fragment_download error={error}"));
        return Err(error);
    }
    Ok(DownloadFragmentsResult { directory: dir.to_string_lossy().into_owned(), total_fragments })
}

struct FragmentArchiveReader {
    response: reqwest::Response,
    buffered: Vec<u8>,
}

impl FragmentArchiveReader {
    fn new(response: reqwest::Response) -> Self { Self { response, buffered: Vec::new() } }

    async fn fill(&mut self, required: usize) -> Result<(), String> {
        while self.buffered.len() < required {
            let chunk = self.response.chunk().await
                .map_err(|error| format!("Fragment archive download failed: {error}"))?
                .ok_or_else(|| "Fragment archive ended before all fragment data was received.".to_string())?;
            self.buffered.extend_from_slice(&chunk);
        }
        Ok(())
    }

    async fn read_exact(&mut self, count: usize) -> Result<Vec<u8>, String> {
        self.fill(count).await?;
        Ok(self.buffered.drain(..count).collect())
    }

    async fn copy_exact(&mut self, mut remaining: u64, destination: &mut File) -> Result<(), String> {
        while remaining > 0 {
            if self.buffered.is_empty() {
                let chunk = self.response.chunk().await
                    .map_err(|error| format!("Fragment archive download failed: {error}"))?
                    .ok_or_else(|| "Fragment archive ended inside a fragment payload.".to_string())?;
                self.buffered.extend_from_slice(&chunk);
            }
            let count = self.buffered.len().min(remaining.min(usize::MAX as u64) as usize);
            destination.write_all(&self.buffered[..count]).await
                .map_err(|error| format!("Cannot write temporary fragment file: {error}"))?;
            self.buffered.drain(..count);
            remaining -= count as u64;
        }
        Ok(())
    }

    async fn ensure_finished(&mut self) -> Result<(), String> {
        if !self.buffered.is_empty() || self.response.chunk().await
            .map_err(|error| format!("Fragment archive download failed: {error}"))?.is_some()
        {
            return Err("Fragment archive contains unexpected trailing data.".into());
        }
        Ok(())
    }
}

async fn get_archive_with_retry(client: &reqwest::Client, url: &str, token: &str) -> Result<reqwest::Response, String> {
    for attempt in 1..=6 {
        match client.get(url).bearer_auth(token).send().await {
            Ok(response) if response.status().is_success() => return Ok(response),
            Ok(response) if (response.status().as_u16() == 429 || response.status().is_server_error()) && attempt < 6 => {
                let status = response.status();
                protection_log("FRAGMENT_ARCHIVE_RETRY", &format!("attempt={attempt} status={status}"));
                tokio::time::sleep(std::time::Duration::from_millis(if status.as_u16() == 429 { 1000 * attempt as u64 } else { 500 * attempt as u64 })).await;
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(format!("Fragment archive download failed (HTTP {status}): {}", redact_secret(&body, token)));
            }
            Err(error) if attempt < 6 && (error.is_connect() || error.is_timeout()) => {
                protection_log("FRAGMENT_ARCHIVE_RETRY", &format!("attempt={attempt} network_error={error}"));
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
            }
            Err(error) => return Err(format!("Fragment archive download failed: {error}")),
        }
    }
    Err("Fragment archive download exhausted its retry limit.".into())
}

#[tauri::command]
async fn restore_local_fragments(fragment_dir: String, password: String, expected_sha256: String) -> Result<RestoreResult, String> {
    let result = tokio::task::spawn_blocking(move || restore_local_fragments_blocking(fragment_dir, password, expected_sha256))
        .await.map_err(|e| format!("restore: local worker failed: {e}"))?;
    if let Err(error) = &result { protection_log("PROTECTION_ERROR", &format!("stage=local_restore error={error}")); }
    result
}

fn restore_local_fragments_blocking(fragment_dir: String, password: String, expected_sha256: String) -> Result<RestoreResult, String> {
    let output_dir = temp_job_dir("output")?;
    let output_path = output_dir.join("restored.bin");
    let fragment_text = fragment_dir;
    let output_text = output_path.to_string_lossy().into_owned();
    let core_fragment_path = core_cli_path(&PathBuf::from(&fragment_text))?;
    let core_output_path = core_cli_path(&output_path)?;
    let result = match run_core("restore", &[&core_fragment_path, &core_output_path], &password) {
        Ok(result) => result,
        Err(error) => { let _ = fs::remove_dir_all(&output_dir); return Err(error); }
    };
    let sha256 = match result["sha256"].as_str() {
        Some(value) => value.to_string(),
        None => { let _ = fs::remove_dir_all(&output_dir); return Err("restore: C++ core omitted SHA-256".into()); }
    };
    if !sha256.eq_ignore_ascii_case(&expected_sha256) {
        let _ = fs::remove_dir_all(&output_dir);
        return Err("restore: output SHA-256 does not match protected metadata".into());
    }
    protection_log("RESTORE_LOCAL_HASH", &format!("verified_sha256={sha256}"));
    Ok(RestoreResult { sha256, output_path: output_text, output_dir: output_dir.to_string_lossy().into_owned() })
}

#[cfg(test)]
fn validate_json_content_type(headers: &reqwest::header::HeaderMap) -> Result<(), String> {
    let content_type = headers.get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .ok_or_else(|| "Server response is missing a valid Content-Type.".to_string())?;
    if content_type != "application/json" && !content_type.ends_with("+json") {
        return Err(format!("Unexpected server Content-Type for fragment metadata: {content_type}."));
    }
    Ok(())
}

#[tauri::command]
fn remove_temp_path(path: String) -> Result<(), String> {
    let root = env::temp_dir().join("SentinelGate").canonicalize().map_err(|e| e.to_string())?;
    let candidate = PathBuf::from(path);
    let resolved = candidate.canonicalize().map_err(|e| e.to_string())?;
    if !resolved.starts_with(&root) { return Err("Refusing to remove a path outside SentinelGate temporary storage.".into()); }
    if resolved.is_dir() { fs::remove_dir_all(resolved).map_err(|e| e.to_string()) }
    else { fs::remove_file(resolved).map_err(|e| e.to_string()) }
}

#[tauri::command]
fn copy_restored_file(source_path: String, destination_path: String) -> Result<(), String> {
    fs::copy(&source_path, &destination_path).map_err(|e| format!("Could not save restored file: {e}"))?;
    fs::remove_file(source_path).ok();
    Ok(())
}

#[tauri::command]
fn api_base_url() -> Result<String, String> {
    let path = package_dir()?.join("config.js");
    let source = fs::read_to_string(&path).map_err(|_| format!("Cannot read {}", path.display()))?;
    let server = source.lines().find_map(|line| {
        let line = line.trim();
        let value = line.strip_prefix("window.SERVER_URL")?.split_once('=')?.1.trim().trim_end_matches(';').trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        Some(value.to_string())
    }).ok_or_else(|| format!("Set SERVER_URL in {}", path.display()))?;
    if server.contains('<') || !(server.starts_with("https://") || cfg!(debug_assertions) && server.starts_with("http://")) {
        return Err(format!("Set the production HTTPS SERVER_URL in {} before launching Sentinel.", path.display()));
    }
    Ok(format!("{}/api", server.trim_end_matches('/')))
}

#[cfg(windows)]
fn show_startup_error(message: &str) {
    use std::os::windows::ffi::OsStrExt;
    let title: Vec<u16> = std::ffi::OsStr::new("SentinelGate").encode_wide().chain(Some(0)).collect();
    let text: Vec<u16> = std::ffi::OsStr::new(message).encode_wide().chain(Some(0)).collect();
    #[link(name = "user32")]
    unsafe extern "system" { fn MessageBoxW(hwnd: *mut std::ffi::c_void, text: *const u16, title: *const u16, kind: u32) -> i32; }
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), 0x10); }
}

// The Windows release intentionally uses the GUI's full existing motion rules.
// WebView2 otherwise mirrors SPI_GETCLIENTAREAANIMATION as
// prefers-reduced-motion: reduce, which collapses the app's existing transitions
// and also makes the About terminal skip its split/back timing.
#[cfg(all(windows, not(debug_assertions)))]
fn configure_full_webview_motion() {
    const MOTION_ARG: &str = "--force-prefers-no-reduced-motion";
    let existing = env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").unwrap_or_default();
    let mut args: Vec<&str> = existing
        .split_whitespace()
        .filter(|arg| {
            !arg.starts_with("--force-prefers-reduced-motion")
                && !arg.starts_with("--force-prefers-no-reduced-motion")
        })
        .collect();
    args.push(MOTION_ARG);
    // This runs before Tauri creates WebView2 and before its worker threads start.
    unsafe { env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", args.join(" ")); }
}

#[cfg(windows)]
fn webview2_is_installed() -> bool {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    for base in [r"SOFTWARE\Microsoft\EdgeUpdate\Clients", r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients"] {
        if let Ok(clients) = root.open_subkey(base) {
            for key_name in clients.enum_keys().flatten() {
                if let Ok(key) = clients.open_subkey(key_name) {
                    let name: String = key.get_value("name").unwrap_or_default();
                    let version: String = key.get_value("pv").unwrap_or_default();
                    if name.to_ascii_lowercase().contains("webview2") && !version.is_empty() && version != "0.0.0.0" { return true; }
                }
            }
        }
    }
    false
}

#[cfg(windows)]
fn preflight() -> Result<(), String> {
    if !webview2_is_installed() {
        let setup = package_dir()?.join("runtime").join("MicrosoftEdgeWebview2Setup.exe");
        if !setup.is_file() { return Err("Microsoft Edge WebView2 Runtime is missing and its bundled installer was not found in runtime/.".into()); }
        let mut installer = Command::new(setup)
            .args(["/silent", "/install"])
            .spawn()
            .map_err(|e| format!("Cannot start the required WebView2 runtime installer: {e}"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = installer.try_wait().map_err(|e| format!("Cannot check WebView2 installer status: {e}"))? {
                if !status.success() { return Err("WebView2 installation did not complete. Connect to the Internet and retry Sentinel.exe.".into()); }
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = installer.kill();
                let _ = installer.wait();
                return Err("WebView2 runtime installation timed out after 60 seconds. Install Microsoft Edge WebView2 Runtime and retry Sentinel.exe.".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    Ok(())
}

fn main() {
    #[cfg(all(windows, not(debug_assertions)))]
    configure_full_webview_motion();

    #[cfg(windows)]
    if let Err(error) = preflight() { show_startup_error(&error); return; }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|_app| {
            prune_stale_restore_output_dirs();
            prune_stale_protection_temp_dirs();
            if let Ok(storage) = local_storage_root() {
                if let Err(error) = fs::create_dir_all(&storage) {
                    protection_log("LOCAL_STORAGE_INIT_ERROR", &format!("path={} error={error}", storage.display()));
                }
            } else {
                protection_log("LOCAL_STORAGE_INIT_ERROR", "LOCALAPPDATA is unavailable; storage will be checked when protection starts");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![open_external_url, selected_file_info, download_track_audio, protect_local_file, upload_fragment, download_fragments, restore_local_fragments, copy_restored_file, remove_temp_path, api_base_url, persist_local_protected_job, local_protected_job_directory, list_local_protected_jobs])
        .run(tauri::generate_context!())
        .expect("error while running SentinelGate desktop client");
}

#[cfg(test)]
mod integration_tests {
    use super::{api_request_headers, audio_signature, download_fragments, download_track_audio, is_expected_pcm_wav_header, is_expired_track_response, protect_local_file_blocking, prune_stale_directories, restore_local_fragments_blocking, upload_fragment, validate_binary_content_type, Path, PathBuf};
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
    use std::{env, fs, io::{Read, Write}, sync::{Mutex, OnceLock}};
    use uuid::Uuid;

    static PACKAGED_CORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn every_native_api_client_inherits_ngrok_bypass_header() {
        assert_eq!(
            api_request_headers().get("ngrok-skip-browser-warning"),
            Some(&HeaderValue::from_static("true"))
        );
    }

    #[test]
    fn carrier_audio_request_sends_bearer_auth_and_ngrok_header() {
        use std::io::{BufRead, Write};
        let audio = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../SentinelGate_CPP_SOURCE/sentinelgate/test.wav");
        let payload = fs::read(&audio).unwrap();
        let expected_payload = payload.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() { break; }
                request.push_str(&line);
            }
            let request_lower = request.to_ascii_lowercase();
            assert!(request.starts_with("GET /api/music/tracks/XGrvLJG8tuM/audio HTTP/1.1"));
            assert!(request_lower.contains("authorization: bearer fixture-audio-token\r\n"));
            assert!(request_lower.contains("ngrok-skip-browser-warning: true\r\n"));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", expected_payload.len()).unwrap();
            stream.write_all(&expected_payload).unwrap();
        });
        let downloaded = tauri::async_runtime::block_on(download_track_audio(
            format!("http://{address}/api"), "fixture-audio-token".into(), "XGrvLJG8tuM".into()
        )).unwrap();
        server.join().unwrap();
        assert_eq!(fs::read(&downloaded).unwrap(), payload);
        fs::remove_dir_all(Path::new(&downloaded).parent().unwrap()).unwrap();
    }

    #[test]
    fn carrier_audio_http_401_is_auth_error_not_network_error() {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() { break; }
                request.push_str(&line);
            }
            assert!(request.to_ascii_lowercase().contains("authorization: bearer fixture-audio-token\r\n"));
            let body = b"{\"status\":\"error\",\"message\":\"Yeu cau token xac thuc!\"}";
            write!(stream, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(body).unwrap();
        });
        let error = tauri::async_runtime::block_on(download_track_audio(
            format!("http://{address}/api"), "fixture-audio-token".into(), "XGrvLJG8tuM".into()
        )).unwrap_err();
        server.join().unwrap();
        assert!(error.starts_with("AUDIO_DOWNLOAD_AUTH:"), "unexpected error: {error}");
        assert!(!error.contains("AUDIO_DOWNLOAD_NETWORK"));
    }

    #[test]
    fn only_http_410_track_expired_contract_gets_expired_track_mapping() {
        assert!(is_expired_track_response(reqwest::StatusCode::GONE, r#"{"error":{"code":"TRACK_EXPIRED"}}"#));
        assert!(is_expired_track_response(reqwest::StatusCode::GONE, r#"{"code":"TRACK_EXPIRED"}"#));
        assert!(!is_expired_track_response(reqwest::StatusCode::INTERNAL_SERVER_ERROR, r#"{"code":"TRACK_EXPIRED"}"#));
        assert!(!is_expired_track_response(reqwest::StatusCode::GONE, r#"{"error":{"code":"OTHER"}}"#));
        assert!(!is_expired_track_response(reqwest::StatusCode::GONE, "not json"));
    }

    #[test]
    fn audio_and_fragment_content_types_reject_html_interstitials() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("audio/mpeg"));
        assert!(validate_binary_content_type(&headers, true).is_ok());
        assert!(validate_binary_content_type(&headers, false).is_err());

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        assert!(validate_binary_content_type(&headers, false).is_ok());

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        assert!(validate_binary_content_type(&headers, true).is_err());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(validate_binary_content_type(&headers, true).is_err());
        headers.clear();
        assert!(validate_binary_content_type(&headers, true).is_err());
    }

    #[test]
    fn fragment_metadata_rejects_html_and_accepts_json() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        assert!(super::validate_json_content_type(&headers).is_ok());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        assert!(super::validate_json_content_type(&headers).is_err());
        headers.clear();
        assert!(super::validate_json_content_type(&headers).is_err());
    }

    #[test]
    fn restore_archive_download_extracts_256_fragments_from_one_archive_request() {
        use std::io::{BufRead, Write};
        let job_id = "0123456789abcdef0123456789abcdef";
        let sha256 = "a".repeat(64);
        let payloads: Vec<Vec<u8>> = (0..256).map(|index| vec![index as u8, 0x53, 0x47]).collect();
        let fragments: Vec<serde_json::Value> = payloads.iter().enumerate().map(|(index, bytes)| {
            serde_json::json!({ "index": index, "name": format!("fragment-{index}.bin"), "sizeBytes": bytes.len() })
        }).collect();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "success": true, "jobId": job_id, "fileIndex": 0, "sha256": sha256,
            "fragments": fragments
        })).unwrap();
        let mut archive = b"SGFRAG1\n".to_vec();
        archive.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        archive.extend_from_slice(&manifest);
        for payload in &payloads { archive.extend_from_slice(payload); }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let archive_server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() { break; }
                request_head.push_str(&line);
            }
            assert!(request_head.starts_with(&format!("GET /api/protection/client-jobs/{job_id}/files/0/fragments/archive HTTP/1.1")));
            assert!(request_head.to_ascii_lowercase().contains("authorization: bearer fixture-archive-token"));
            assert!(request_head.to_ascii_lowercase().contains("ngrok-skip-browser-warning: true"));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-SentinelGate-Archive: SGFRAG1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", archive.len()).unwrap();
            stream.write_all(&archive).unwrap();
        });

        let downloaded = tauri::async_runtime::block_on(download_fragments(
            format!("http://{address}/api"), "fixture-archive-token".into(),
            job_id.into(), 0, sha256,
        )).unwrap();
        archive_server.join().unwrap();
        assert_eq!(downloaded.total_fragments, 256);
        let directory = PathBuf::from(&downloaded.directory);
        for (index, expected) in payloads.iter().enumerate() {
            assert_eq!(fs::read(directory.join(format!("fragment-{index}.bin"))).unwrap(), *expected);
        }
        super::remove_temp_path(downloaded.directory).unwrap();
    }

    #[test]
    fn audio_signature_accepts_supported_containers_and_rejects_html() {
        assert_eq!(audio_signature(b"RIFF\x00\x00\x00\x00WAVEfmt "), Some("wav"));
        assert_eq!(audio_signature(b"fLaC\x00\x00\x00\x22"), Some("flac"));
        assert_eq!(audio_signature(b"OggS\x00\x02\x00\x00\x00\x00\x00\x00"), Some("ogg"));
        assert_eq!(audio_signature(b"ID3\x04\x00\x00\x00\x00\x00\x00"), Some("mpeg"));
        assert_eq!(audio_signature(b"<html><body>ngrok"), None);
    }

    #[test]
    fn cxx_audio_fixture_uses_supported_pcm_wav_header() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../SentinelGate_CPP_SOURCE/sentinelgate/test.wav");
        let mut header = [0u8; 44];
        fs::File::open(&fixture).unwrap().read_exact(&mut header).unwrap();
        assert!(is_expected_pcm_wav_header(&header), "C++ WAV fixture header is not the selected conversion format");
    }

    #[test]
    fn audio_header_rejects_mp3_and_non_pcm_wave() {
        let mut header = [0u8; 44];
        header[0..4].copy_from_slice(b"RIFF");
        header[8..12].copy_from_slice(b"WAVE");
        header[12..16].copy_from_slice(b"fmt ");
        header[16..20].copy_from_slice(&16u32.to_le_bytes());
        header[20..22].copy_from_slice(&1u16.to_le_bytes());
        header[22..24].copy_from_slice(&1u16.to_le_bytes());
        header[24..28].copy_from_slice(&44100u32.to_le_bytes());
        header[34..36].copy_from_slice(&16u16.to_le_bytes());
        assert!(is_expected_pcm_wav_header(&header));
        header[20..22].copy_from_slice(&3u16.to_le_bytes());
        assert!(!is_expected_pcm_wav_header(&header));
    }

    #[test]
    fn run_core_refuses_raw_carrier_bin_for_protect() {
        let error = super::run_core("protect", &["input.txt", "carrier-audio.bin", "out"], "")
            .expect_err("raw downloaded carrier must never reach C++ protect");
        assert!(error.contains("LOCAL_CORE_AUDIO_FORMAT_ERROR"));
        assert!(error.contains("carrier-normalized.wav"));
    }

    #[test]
    fn cxx_json_windows_unicode_paths_are_parsed_as_json() {
        let output = br#"{"status":"success","outputDir":"C:\\Users\\T\u00e9st\\file with space","fragments":1}"#;
        let parsed: serde_json::Value = serde_json::from_slice(output).unwrap();
        assert_eq!(parsed["outputDir"], "C:\\Users\\T\u{00e9}st\\file with space");
        assert_eq!(parsed["fragments"], 1);
    }

    #[cfg(windows)]
    #[test]
    fn packaged_sidecar_path_injection_protect_restore_and_reject_corruption() {
        let _guard = PACKAGED_CORE_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let test_exe = std::env::current_exe().unwrap();
        let package = test_exe.parent().unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fs::copy(source.join("bin/sentinelgate.exe"), package.join("sentinelgate.exe")).unwrap();
        let source_runtime = source.join("bin/runtime");
        let runtime = package.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        for entry in fs::read_dir(source_runtime).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), runtime.join(entry.file_name())).unwrap();
            }
        }

        let work = env::temp_dir().join(format!("SentinelGate T\u{1ec7}p ti\u{1ebf}ng Vi\u{1ec7}t {}", Uuid::new_v4()));
        fs::create_dir_all(&work).unwrap();
        let input = work.join("t\u{1ec7}p \u{0111}\u{1ea7}u v\u{00e0}o ti\u{1ebf}ng Vi\u{1ec7}t.txt");
        fs::write(&input, b"Windows packaged run_core integration test").unwrap();
        let audio = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../SentinelGate_CPP_SOURCE/sentinelgate/test.wav");
        assert!(audio.is_file(), "audio fixture missing: {}", audio.display());

        let protected = protect_local_file_blocking(
            input.to_string_lossy().into_owned(), audio.to_string_lossy().into_owned(), "TestPass-2026!".into()
        ).unwrap();
        assert!(protected.total_fragments > 0);
        assert_eq!(protected.fragment_paths.len(), protected.total_fragments);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected_fragment = fs::read(&protected.fragment_paths[0]).unwrap();
        let upload_expected = expected_fragment.clone();
        let upload_server = std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() { break; }
                request_head.push_str(&line);
            }
            let content_length = request_head.lines()
                .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|value| value.trim().parse::<usize>().unwrap()))
                .unwrap();
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            assert!(request_head.starts_with("PUT /api/protection/client-jobs/0123456789abcdef0123456789abcdef/files/0/fragments/0 HTTP/1.1"));
            assert!(request_head.to_ascii_lowercase().contains("authorization: bearer fixture-upload-token"));
            assert!(request_head.to_ascii_lowercase().contains("content-type: application/octet-stream"));
            assert!(request_head.to_ascii_lowercase().contains("ngrok-skip-browser-warning: true"));
            assert_eq!(body, upload_expected);
            let response_body = format!("{{\"success\":true,\"fragmentIndex\":0,\"sizeBytes\":{}}}", upload_expected.len());
            write!(stream, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_body.len()).unwrap();
            stream.write_all(response_body.as_bytes()).unwrap();
        });
        tauri::async_runtime::block_on(upload_fragment(
            format!("http://{address}/api"), "fixture-upload-token".into(),
            "0123456789abcdef0123456789abcdef".into(), 0, 0, protected.fragment_paths[0].clone()
        )).unwrap();
        upload_server.join().unwrap();

        let error_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let error_address = error_listener.local_addr().unwrap();
        let error_server = std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            let (mut stream, _) = error_listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() { break; }
                request_head.push_str(&line);
            }
            let content_length = request_head.lines()
                .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|value| value.trim().parse::<usize>().unwrap()))
                .unwrap();
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let response_body = b"{\"success\":false,\"error\":{\"code\":\"LIMIT_FILE_SIZE\",\"message\":\"fixture upload rejection\"}}";
            write!(stream, "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_body.len()).unwrap();
            stream.write_all(response_body).unwrap();
        });
        let rejected = tauri::async_runtime::block_on(upload_fragment(
            format!("http://{error_address}/api"), "fixture-upload-token".into(),
            "0123456789abcdef0123456789abcdef".into(), 0, 0, protected.fragment_paths[0].clone()
        )).unwrap_err();
        error_server.join().unwrap();
        assert!(rejected.contains("HTTP 413"));
        assert!(rejected.contains("fixture upload rejection"));

        let restored = restore_local_fragments_blocking(
            protected.work_dir.clone(), "TestPass-2026!".into(), protected.sha256.clone()
        ).unwrap();
        assert_eq!(fs::read(&input).unwrap(), fs::read(&restored.output_path).unwrap());
        assert_eq!(restored.sha256, protected.sha256);

        let wrong = restore_local_fragments_blocking(
            protected.work_dir.clone(), "Wrong-Pass-2026!".into(), protected.sha256.clone()
        );
        assert!(wrong.is_err(), "wrong password unexpectedly restored data");

        let modified_dir = work.join("modified fragments");
        fs::create_dir_all(&modified_dir).unwrap();
        for fragment in &protected.fragment_paths {
            let source = PathBuf::from(fragment);
            fs::copy(&source, modified_dir.join(source.file_name().unwrap())).unwrap();
        }
        let modified = fs::read_dir(&modified_dir).unwrap().next().unwrap().unwrap().path();
        let mut bytes = fs::read(&modified).unwrap();
        bytes[0] ^= 1;
        fs::write(modified, bytes).unwrap();
        let corrupt = restore_local_fragments_blocking(
            modified_dir.to_string_lossy().into_owned(), "TestPass-2026!".into(), protected.sha256.clone()
        );
        assert!(corrupt.is_err(), "modified fragment unexpectedly restored");

        let _ = fs::remove_dir_all(&work);
    }

    #[cfg(windows)]
    #[test]
    fn packaged_256_fragment_local_storage_protect_restore_e2e() {
        let _guard = PACKAGED_CORE_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let local_app_data = env::var_os("SENTINEL_E2E_LOCALAPPDATA")
            .map(PathBuf::from)
            .expect("set SENTINEL_E2E_LOCALAPPDATA to an isolated test profile; refusing to touch the real profile");
        assert_eq!(env::var_os("LOCALAPPDATA").map(PathBuf::from), Some(local_app_data.clone()));
        let storage = super::local_storage_root().unwrap();
        assert_eq!(storage, local_app_data.join("SentinelGate").join("storage"));

        let test_exe = env::current_exe().unwrap();
        let package = test_exe.parent().unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fs::copy(source.join("bin/sentinelgate.exe"), package.join("sentinelgate.exe")).unwrap();
        let source_runtime = source.join("bin/runtime");
        let runtime = package.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        for entry in fs::read_dir(source_runtime).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() { fs::copy(entry.path(), runtime.join(entry.file_name())).unwrap(); }
        }

        let work = env::temp_dir().join(format!("SentinelGate local 256 {}", Uuid::new_v4()));
        fs::create_dir_all(&work).unwrap();
        let input = work.join("large-input.bin");
        let mut input_file = fs::File::create(&input).unwrap();
        let input_chunk = vec![0x5a; 1024 * 1024];
        for _ in 0..64 { input_file.write_all(&input_chunk).unwrap(); }
        input_file.sync_all().unwrap();

        let audio = work.join("carrier.wav");
        write_beat_carrier_wav(&audio, 1000);
        let password = "Sentinel-Local-256-E2E-Only!".to_string();
        let normalized_temp_root = env::temp_dir().join("SentinelGate").join("audio-normalized");
        let normalized_temp_before = count_directories(&normalized_temp_root);
        let protected = protect_local_file_blocking(input.to_string_lossy().into_owned(), audio.to_string_lossy().into_owned(), password.clone()).unwrap();
        assert_eq!(count_directories(&normalized_temp_root), normalized_temp_before, "normalized carrier temp should be cleaned after Protect");
        assert_eq!(protected.total_fragments, 256, "real packaged Protect core must generate exactly 256 fragments");
        assert_eq!(protected.fragment_paths.len(), 256);

        let job_id = Uuid::new_v4().simple().to_string();
        let owner_id = "local-256-e2e-owner";
        let files = vec![super::LocalProtectedFile {
            index: 0, original_name: "large-input.bin".into(), size_bytes: fs::metadata(&input).unwrap().len(),
            sha256: protected.sha256.clone(), total_fragments: protected.total_fragments,
            fragment_paths: protected.fragment_paths.clone(),
        }];
        let manifest = super::persist_local_protected_job_at(&storage, &job_id, owner_id, &files).unwrap();
        assert_eq!(manifest["files"][0]["fragments"].as_array().unwrap().len(), 256);
        let listed = super::list_local_protected_jobs().unwrap();
        let readback = listed.iter().find(|entry| entry["jobId"] == job_id).unwrap();
        assert_eq!(readback["localIntegrity"], true);
        assert_eq!(readback["ownerId"], owner_id);
        assert_eq!(readback["files"][0]["totalFragments"], 256);

        let job_dir = storage.join(&job_id);
        let fragment_dir = PathBuf::from(super::resolve_local_protected_job_directory(&job_dir, &job_id, owner_id, 0, &protected.sha256).unwrap());
        let mut names = fs::read_dir(&fragment_dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect::<Vec<_>>();
        names.sort_by_key(|name| name.strip_prefix("fragment-").and_then(|value| value.strip_suffix(".bin")).and_then(|value| value.parse::<usize>().ok()).unwrap_or(usize::MAX));
        assert_eq!(names, (0..256).map(|index| format!("fragment-{index}.bin")).collect::<Vec<_>>(), "persistent fragment names must encode the full ordered sequence");

        fs::remove_dir_all(&protected.work_dir).unwrap();
        assert!(!Path::new(&protected.work_dir).exists(), "Protect temp output should be cleaned after local storage commit");
        let restored = restore_local_fragments_blocking(fragment_dir.to_string_lossy().into_owned(), password, protected.sha256.clone()).unwrap();
        assert_eq!(restored.sha256, protected.sha256, "C++ Restore verifies fragment HMAC and output SHA-256");
        assert_files_equal(&input, Path::new(&restored.output_path));
        assert_eq!(fs::read_dir(&fragment_dir).unwrap().count(), 256, "protected fragments must remain after Restore");
        fs::remove_dir_all(&restored.output_dir).unwrap();
        assert!(!Path::new(&restored.output_dir).exists(), "Restore plaintext temp should be cleaned after output verification");

        let missing = fragment_dir.join("fragment-132.bin");
        let missing_bytes = fs::read(&missing).unwrap();
        fs::remove_file(&missing).unwrap();
        let missing_result = super::resolve_local_protected_job_directory(&job_dir, &job_id, owner_id, 0, &protected.sha256);
        assert!(missing_result.unwrap_err().contains("FRAGMENT_MISSING"), "a missing fragment must fail before the C++ decrypt/merge command is invoked");
        fs::write(&missing, missing_bytes).unwrap();
        assert_eq!(fs::read_dir(&fragment_dir).unwrap().count(), 256, "restore the test fragment after the missing-fragment case");

        fs::remove_dir_all(&job_dir).unwrap();
        fs::remove_dir_all(&work).unwrap();
    }

    #[cfg(windows)]
    fn write_beat_carrier_wav(path: &Path, duration_seconds: u32) {
        let sample_rate = 44_100u32;
        let sample_count = sample_rate * duration_seconds;
        let data_bytes = sample_count * 2;
        let mut file = std::io::BufWriter::new(fs::File::create(path).unwrap());
        file.write_all(b"RIFF").unwrap(); file.write_all(&(data_bytes + 36).to_le_bytes()).unwrap(); file.write_all(b"WAVE").unwrap();
        file.write_all(b"fmt ").unwrap(); file.write_all(&16u32.to_le_bytes()).unwrap(); file.write_all(&1u16.to_le_bytes()).unwrap();
        file.write_all(&1u16.to_le_bytes()).unwrap(); file.write_all(&sample_rate.to_le_bytes()).unwrap(); file.write_all(&(sample_rate * 2).to_le_bytes()).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap(); file.write_all(&16u16.to_le_bytes()).unwrap();
        file.write_all(b"data").unwrap(); file.write_all(&data_bytes.to_le_bytes()).unwrap();
        let silence = [0u8; 32 * 1024];
        let mut cursor = 0u32;
        for beat in 0..(duration_seconds * 2) {
            let start = beat * sample_rate / 2;
            write_wav_silence(&mut file, &silence, (start - cursor) as usize * 2);
            for offset in 0..3200u32 {
                let envelope = 1.0 - f64::from(offset) / 3200.0;
                let sample = (26000.0 * envelope * (2.0 * std::f64::consts::PI * 1000.0 * f64::from(offset) / f64::from(sample_rate)).sin()).round() as i16;
                file.write_all(&sample.to_le_bytes()).unwrap();
            }
            cursor = start + 3200;
        }
        write_wav_silence(&mut file, &silence, (sample_count - cursor) as usize * 2);
        file.flush().unwrap();
    }

    #[cfg(windows)]
    fn write_wav_silence(file: &mut impl Write, buffer: &[u8], mut bytes: usize) {
        while bytes > 0 {
            let amount = bytes.min(buffer.len());
            file.write_all(&buffer[..amount]).unwrap();
            bytes -= amount;
        }
    }

    #[cfg(windows)]
    fn assert_files_equal(left: &Path, right: &Path) {
        use std::io::Read;
        let mut left = std::io::BufReader::new(fs::File::open(left).unwrap());
        let mut right = std::io::BufReader::new(fs::File::open(right).unwrap());
        let mut left_chunk = vec![0u8; 1024 * 1024];
        let mut right_chunk = vec![0u8; 1024 * 1024];
        loop {
            let left_read = left.read(&mut left_chunk).unwrap();
            let right_read = right.read(&mut right_chunk).unwrap();
            assert_eq!(left_read, right_read, "input and restored output sizes differ");
            assert_eq!(&left_chunk[..left_read], &right_chunk[..right_read], "restored bytes differ from the original input");
            if left_read == 0 { break; }
        }
    }

    #[cfg(windows)]
    fn count_directories(path: &Path) -> usize {
        fs::read_dir(path).map(|entries| entries.flatten().filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())).count()).unwrap_or(0)
    }

    #[test]
    fn local_storage_persists_manifest_and_detects_manifest_or_fragment_damage() {
        use super::{local_disk_error, persist_local_protected_job_at, resolve_local_protected_job_directory, LocalProtectedFile};
        let work = env::temp_dir().join(format!("sentinelgate-local-storage-test-{}", Uuid::new_v4()));
        let source_dir = work.join("source");
        let storage = work.join("storage");
        fs::create_dir_all(&source_dir).unwrap();
        let source = source_dir.join("fragment-0.bin");
        fs::write(&source, b"encrypted-fragment-fixture").unwrap();
        let job_id = "abcdef0123456789abcdef0123456789";
        let files = vec![LocalProtectedFile {
            index: 0, original_name: "fixture.bin".into(), size_bytes: 123,
            sha256: "a".repeat(64), total_fragments: 1,
            fragment_paths: vec![source.to_string_lossy().into_owned()],
        }];
        let manifest = persist_local_protected_job_at(&storage, job_id, "fixture-owner", &files).unwrap();
        assert_eq!(manifest["storageMode"], "local");
        assert_eq!(manifest["storageVersion"], 1);
        assert!(manifest.get("password").is_none() && manifest.get("key").is_none());
        let job_dir = storage.join(job_id);
        let fragment_dir = PathBuf::from(resolve_local_protected_job_directory(&job_dir, job_id, "fixture-owner", 0, &"a".repeat(64)).unwrap());
        let saved_fragment = fragment_dir.join("fragment-0.bin");
        assert_eq!(fs::read(&source).unwrap(), fs::read(&saved_fragment).unwrap());
        fs::write(&saved_fragment, b"short").unwrap();
        assert!(resolve_local_protected_job_directory(&job_dir, job_id, "fixture-owner", 0, &"a".repeat(64)).unwrap_err().contains("FRAGMENT_CORRUPT"));
        fs::remove_file(&saved_fragment).unwrap();
        assert!(resolve_local_protected_job_directory(&job_dir, job_id, "fixture-owner", 0, &"a".repeat(64)).unwrap_err().contains("FRAGMENT_MISSING"));
        fs::write(job_dir.join("manifest.json"), b"not-json").unwrap();
        assert!(resolve_local_protected_job_directory(&job_dir, job_id, "fixture-owner", 0, &"a".repeat(64)).unwrap_err().contains("MANIFEST_CORRUPT"));
        assert!(local_disk_error("LOCAL_STORAGE", std::io::Error::from(std::io::ErrorKind::PermissionDenied)).contains("PERMISSION"));
        assert!(local_disk_error("LOCAL_STORAGE", std::io::Error::from_raw_os_error(112)).contains("DISK_FULL"));

        let many_id = "1234567890abcdef1234567890abcdef";
        let many_files = vec![LocalProtectedFile {
            index: 0, original_name: "many-fragments.bin".into(), size_bytes: 123,
            sha256: "c".repeat(64), total_fragments: 256,
            fragment_paths: vec![source.to_string_lossy().into_owned(); 256],
        }];
        let many_manifest = persist_local_protected_job_at(&storage, many_id, "fixture-owner", &many_files).unwrap();
        assert_eq!(many_manifest["files"][0]["fragments"].as_array().unwrap().len(), 256);
        let many_job_dir = storage.join(many_id);
        assert!(resolve_local_protected_job_directory(&many_job_dir, many_id, "fixture-owner", 0, &"c".repeat(64)).is_ok());

        let interrupted_id = "fedcba9876543210fedcba9876543210";
        let interrupted_files = vec![LocalProtectedFile {
            index: 0, original_name: "interrupted.bin".into(), size_bytes: 123,
            sha256: "b".repeat(64), total_fragments: 2,
            fragment_paths: vec![source.to_string_lossy().into_owned(), work.join("missing-fragment.bin").to_string_lossy().into_owned()],
        }];
        assert!(persist_local_protected_job_at(&storage, interrupted_id, "fixture-owner", &interrupted_files).is_err());
        let interrupted_dir = storage.join(interrupted_id);
        assert!(interrupted_dir.join("files/0/fragment-0.bin").is_file(), "completed fragment remains available for recovery");
        assert!(!interrupted_dir.join("manifest.json").exists(), "partial job is not marked complete without a finalized manifest");
        let _ = fs::remove_dir_all(work);
    }

    #[test]
    fn interrupted_restore_temporary_plaintext_is_pruned_from_isolated_stale_directory() {
        let directory = env::temp_dir().join(format!("sentinelgate-restore-prune-test-{}", Uuid::new_v4()));
        let stale = directory.join("interrupted-restore");
        let stale_protect = directory.join("interrupted-protect");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("restored.bin"), b"partial-plaintext").unwrap();
        fs::create_dir_all(&stale_protect).unwrap();
        fs::write(stale_protect.join("fragment-0.bin"), b"encrypted-fragment").unwrap();
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        prune_stale_directories(&directory, future, "TEST_PRUNED", "TEST_PRUNE_ERROR");
        assert!(!stale.exists(), "stale partial restore plaintext should be removed");
        assert!(!stale_protect.exists(), "stale encrypted Protect work data should be removed");
        let _ = fs::remove_dir_all(directory);
    }
}
