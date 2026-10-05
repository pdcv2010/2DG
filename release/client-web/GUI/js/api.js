(function (global) {
    "use strict";

    const configuredServer = typeof global.SERVER_URL === "string" ? global.SERVER_URL.trim().replace(/\/+$/, "") : "";
    let configurationError = null;
    let API_BASE = "";
    try {
        const parsed = new URL(configuredServer);
        if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") throw new Error("SERVER_URL must be an HTTP(S) origin without credentials, path, query, or fragment.");
        if (parsed.protocol === "http:" && !["localhost", "127.0.0.1"].includes(parsed.hostname)) throw new Error("Production SERVER_URL must use HTTPS.");
        API_BASE = `${configuredServer}/api`;
    } catch (error) { configurationError = error; }
    const PUBLIC_ENDPOINTS = new Set(["/auth/register", "/auth/login", "/health"]);
    let sessionEpoch = 0;
    let unauthorizedHandled = false;

    class ApiError extends Error {
        constructor(message, status, payload) {
            super(message);
            this.name = "ApiError";
            this.status = status;
            this.payload = payload;
            this.code = payload?.error?.code || payload?.code;
        }
    }

    class ApiConfigurationError extends Error {
        constructor(message) {
            super(message);
            this.name = "ApiConfigurationError";
            this.kind = "configuration";
        }
    }

    async function apiRequest(endpoint, options = {}) {
        if (configurationError) throw new ApiConfigurationError(`Invalid config.js SERVER_URL: ${configurationError.message}`);
        const method = options.method || "GET";
        const headers = new Headers(options.headers || {});
        headers.set("ngrok-skip-browser-warning", "true");
        const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
        let body = options.body;

        if (body !== undefined && body !== null && !isFormData && typeof body !== "string" && !(body instanceof Blob)) {
            body = JSON.stringify(body);
            if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
        }
        if (!headers.has("Accept")) headers.set("Accept", options.responseType === "blob" ? "*/*" : "application/json");

        const requiresAuth = options.auth ?? !PUBLIC_ENDPOINTS.has(endpoint);
        const requestEpoch = sessionEpoch;
        const token = localStorage.getItem("access_token");
        if (requiresAuth && token) headers.set("Authorization", `Bearer ${token}`);

        const startupRequest = options.startup === true;
        const timeoutMs = options.timeoutMs ?? (startupRequest ? 12000 : 120000);
        const controller = new AbortController();
        let timedOut = false;
        const timeoutId = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
        const abortFromCaller = () => controller.abort(options.signal?.reason);
        if (options.signal?.aborted) abortFromCaller();
        else options.signal?.addEventListener("abort", abortFromCaller, { once: true });

        let response;
        try {
            response = await fetch(`${API_BASE}${endpoint}`, { method, headers, body, signal: controller.signal });
        } catch (error) {
            if (timedOut) {
                const timeout = new ApiError(`Request timed out after ${timeoutMs / 1000} seconds.`, 0);
                timeout.kind = "timeout";
                clearTimeout(timeoutId);
                options.signal?.removeEventListener("abort", abortFromCaller);
                throw timeout;
            }
            if (options.signal?.aborted) {
                clearTimeout(timeoutId);
                options.signal?.removeEventListener("abort", abortFromCaller);
                throw error;
            }
            const network = new ApiError(`Cannot reach API server: ${error?.message || "network request failed"}`, 0);
            network.kind = "network";
            clearTimeout(timeoutId);
            options.signal?.removeEventListener("abort", abortFromCaller);
            throw network;
        }

        try {
        let payload;
        if (options.responseType === "blob") {
            if (!response.ok) {
                try { payload = await response.clone().json(); } catch { payload = {}; }
            } else {
                if (requiresAuth && requestEpoch !== sessionEpoch) throw expiredSessionError();
                return response;
            }
        } else {
            const contentType = response.headers.get("content-type") || "";
            payload = contentType.includes("application/json") ? await response.json() : await response.text();
        }

        if (!response.ok) {
            const responseMessage = payload?.error?.message || payload?.message || (typeof payload === "string" ? payload.trim() : "");
            const error = new ApiError(String(responseMessage || `HTTP ${response.status} ${response.statusText || "request failed"} (response body empty).`), response.status, payload);
            error.statusText = response.statusText;
            error.responseBody = payload;
            // A late response for an old token must not log out a newer session.
            if (response.status === 401 && requiresAuth && token === localStorage.getItem("access_token")) {
                error.sessionReason = token ? "expired" : "missing";
                invalidateSession(error.sessionReason);
            }
            throw error;
        }
        // Do not let requests started before session expiry update the current UI.
        if (requiresAuth && requestEpoch !== sessionEpoch) throw expiredSessionError();
        return payload;
        } catch (error) {
            if (timedOut) {
                const timeout = new ApiError(`Request timed out after ${timeoutMs / 1000} seconds.`, 0);
                timeout.kind = "timeout";
                throw timeout;
            }
            if (error instanceof TypeError && !options.signal?.aborted) {
                const network = new ApiError(`Cannot read API response: ${error.message}`, 0);
                network.kind = "network";
                throw network;
            }
            if (error instanceof SyntaxError) {
                const invalid = new ApiError(`HTTP ${response.status} returned invalid JSON: ${error.message}`, response.status);
                invalid.kind = "invalid-json";
                invalid.cause = error;
                throw invalid;
            }
            throw error;
        } finally {
            clearTimeout(timeoutId);
            options.signal?.removeEventListener("abort", abortFromCaller);
        }
    }

    function expiredSessionError() {
        return new ApiError("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.", 401);
    }

    function invalidateSession(reason = "expired") {
        clearSession();
        if (unauthorizedHandled) return;
        unauthorizedHandled = true;
        sessionEpoch += 1;
        global.dispatchEvent(new CustomEvent("sentinelgate:unauthorized", { detail: { reason } }));
    }

    function saveSession(payload) {
        if (!payload?.token || !payload?.user) throw new ApiError("Phản hồi đăng nhập thiếu token hoặc thông tin người dùng.", 500, payload);
        localStorage.setItem("access_token", payload.token);
        localStorage.setItem("user", JSON.stringify(payload.user));
        unauthorizedHandled = false;
        return payload;
    }

    function clearSession() {
        localStorage.removeItem("access_token");
        localStorage.removeItem("user");
    }

    const client = {
        API_BASE,
        ApiError,
        apiRequest,
        async register({ username, email, password }) {
            return saveSession(await apiRequest("/auth/register", { method: "POST", body: { username, email, password } }));
        },
        async login({ email, password }) {
            return saveSession(await apiRequest("/auth/login", { method: "POST", body: { email, password } }));
        },
        logout: clearSession,
        get configurationError() { return configurationError ? new ApiConfigurationError(`Invalid config.js SERVER_URL: ${configurationError.message}`) : null; },
        health: (options = {}) => apiRequest("/health", { ...options, auth: false }),
        session: (options = {}) => apiRequest("/auth/session", options),
        dashboardStats: (options = {}) => apiRequest("/dashboard/stats", options),
        protectionJobs: () => apiRequest("/protection/jobs"),
        restoreJobs: () => apiRequest("/restore/jobs"),
        searchMusic: (query, options = {}) => apiRequest(`/music/search?query=${encodeURIComponent(query)}`, options),
        createClientProtectionJob(files, storageMode = "server") {
            return apiRequest("/protection/client-jobs", { method: "POST", body: { files, storageMode, storageVersion: storageMode === "local" ? 1 : undefined } });
        },
        completeClientProtectionJob(id, metadata) {
            return apiRequest(`/protection/client-jobs/${encodeURIComponent(id)}/complete`, { method: "POST", body: metadata });
        },
        heartbeatClientProtectionJob(id) {
            return apiRequest(`/protection/client-jobs/${encodeURIComponent(id)}/heartbeat`, { method: "POST", body: {} });
        },
        failClientProtectionJob(id, code) {
            return apiRequest(`/protection/client-jobs/${encodeURIComponent(id)}/fail`, { method: "POST", body: { code } });
        },
        recordClientRestore({ protectJobId, fileIndex, sha256 }) {
            return apiRequest("/restore/client-jobs", {
                method: "POST",
                body: { protectJobId, fileIndex, sha256 }
            });
        },
    };

    global.SentinelGateApi = client;
})(window);
