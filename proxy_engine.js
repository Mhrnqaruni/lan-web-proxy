"use strict";

const crypto = require("node:crypto");
const dns = require("node:dns").promises;
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const {
  RammerheadJSMemCache,
  RammerheadLogging,
  RammerheadProxy,
  RammerheadSession,
  RammerheadSessionFileCache,
} = require("rammerhead");
const urlUtils = require("testcafe-hammerhead/lib/utils/url");

const APP_NAME = "LAN Web Proxy";
const AUTH_COOKIE = "lan_proxy_auth";
const HOST = process.env.LAN_PROXY_HOST || "0.0.0.0";
const PORT = parsePort(process.env.LAN_PROXY_PORT || "8080", "LAN_PROXY_PORT");
const CROSS_PORT = parsePort(process.env.LAN_PROXY_CROSS_PORT || String(PORT + 1), "LAN_PROXY_CROSS_PORT");
const TLS_ENABLED = process.env.LAN_PROXY_TLS_ENABLED !== "0";
const TLS_CERT_PATH = process.env.LAN_PROXY_TLS_CERT;
const TLS_KEY_PATH = process.env.LAN_PROXY_TLS_KEY;
const PUBLIC_PROTOCOL = process.env.LAN_PROXY_PUBLIC_PROTOCOL || (TLS_ENABLED ? "https:" : "http:");
const PUBLIC_PORT = parsePort(process.env.LAN_PROXY_PUBLIC_PORT || String(PORT), "LAN_PROXY_PUBLIC_PORT");
const PUBLIC_CROSS_PORT = parsePort(process.env.LAN_PROXY_PUBLIC_CROSS_PORT || String(CROSS_PORT), "LAN_PROXY_PUBLIC_CROSS_PORT");
const PUBLIC_HOSTNAME = (process.env.LAN_PROXY_PUBLIC_HOSTNAME || "").trim().toLowerCase().replace(/\.$/, "");
const ACCESS_TOKEN = process.env.LAN_PROXY_TOKEN || crypto.randomBytes(24).toString("base64url");
const CONTROL_TOKEN = process.env.LAN_PROXY_CONTROL_TOKEN || crypto.randomBytes(24).toString("base64url");
const DATA_DIR = path.resolve(process.env.LAN_PROXY_DATA_DIR || path.join(__dirname, ".proxy_data"));
const ALLOW_PRIVATE_TARGETS = process.env.LAN_PROXY_ALLOW_PRIVATE_TARGETS === "1";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;
const MAX_FORM_BYTES = 8 * 1024;
const MAX_DIAGNOSTIC_BYTES = 32 * 1024;

function parsePort(value, name) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be an integer from 1 through 65535.`);
  }
  return port;
}

if (PORT === CROSS_PORT) {
  throw new Error("The main port and cross-domain port must be different.");
}
if (!["http:", "https:"].includes(PUBLIC_PROTOCOL)) {
  throw new Error("LAN_PROXY_PUBLIC_PROTOCOL must be http: or https:.");
}
if (PUBLIC_HOSTNAME && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(PUBLIC_HOSTNAME)) {
  throw new Error("LAN_PROXY_PUBLIC_HOSTNAME must be a valid DNS hostname.");
}
if (TLS_ENABLED && (!TLS_CERT_PATH || !TLS_KEY_PATH)) {
  throw new Error("LAN_PROXY_TLS_CERT and LAN_PROXY_TLS_KEY are required.");
}

const tlsOptions = TLS_ENABLED
  ? {
      cert: fs.readFileSync(TLS_CERT_PATH),
      key: fs.readFileSync(TLS_KEY_PATH),
      minVersion: "TLSv1.2",
    }
  : null;

fs.mkdirSync(DATA_DIR, { recursive: true });
const sessionsDirectory = path.join(DATA_DIR, "sessions");
fs.mkdirSync(sessionsDirectory, { recursive: true });
const diagnosticLogPath = path.resolve(process.env.LAN_PROXY_DIAGNOSTIC_LOG || path.join(DATA_DIR, "diagnostics.jsonl"));
const diagnosticStream = fs.createWriteStream(diagnosticLogPath, { flags: "a", encoding: "utf8" });
diagnosticStream.on("error", (error) => console.error(`${APP_NAME}: diagnostic log error:`, error.message));

function truncateDiagnostic(value, limit = 1200) {
  return String(value == null ? "" : value).replace(/[\r\n\0]+/g, " ").slice(0, limit);
}

function safeDiagnosticUrl(value) {
  try {
    const parsed = new URL(String(value));
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`.slice(0, 1600);
  } catch {
    return truncateDiagnostic(String(value || "").split(/[?#]/, 1)[0], 300);
  }
}

function safeDiagnosticMessage(value, limit = 1000) {
  const withoutQueryValues = String(value == null ? "" : value).replace(
    /https?:\/\/[^\s"'<>]+/gi,
    (match) => safeDiagnosticUrl(match),
  );
  return truncateDiagnostic(withoutQueryValues, limit);
}

function diagnosticLog(type, details = {}) {
  const record = { timestamp: new Date().toISOString(), type, ...details };
  diagnosticStream.write(`${JSON.stringify(record)}\n`);
}

function headerFromWriteHeadArgs(args, name) {
  const wanted = name.toLowerCase();
  const headers = [...args].reverse().find((value) => value && typeof value === "object");
  if (Array.isArray(headers)) {
    for (let index = 0; index + 1 < headers.length; index += 2) {
      if (String(headers[index]).toLowerCase() === wanted) return headers[index + 1];
    }
    return "";
  }
  if (headers) {
    const key = Object.keys(headers).find((value) => value.toLowerCase() === wanted);
    return key ? headers[key] : "";
  }
  return "";
}

function isInstagramFamilyUrl(value) {
  try {
    const hostname = new URL(String(value)).hostname.toLowerCase();
    return ["instagram.com", "facebook.com", "fbcdn.net", "cdninstagram.com", "fbsbx.com", "meta.com"]
      .some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  } catch {
    return false;
  }
}

function recordBrowserReport(report, transport, proxyPort = 0) {
  if (!report || typeof report !== "object" || Array.isArray(report)) return;
  diagnosticLog("browser_report", {
    transport,
    reportType: truncateDiagnostic(report.type, 80),
    page: safeDiagnosticUrl(report.page || ""),
    isSecureContext: Boolean(report.isSecureContext),
    serviceWorkerAvailable: Boolean(report.serviceWorkerAvailable),
    cookieEnabled: Boolean(report.cookieEnabled),
    message: safeDiagnosticMessage(report.message, 1000),
    source: safeDiagnosticUrl(report.source || ""),
    line: Number(report.line) || 0,
    column: Number(report.column) || 0,
    tag: truncateDiagnostic(report.tag, 80),
    resource: safeDiagnosticUrl(report.resource || ""),
    userAgent: truncateDiagnostic(report.userAgent, 500),
    proxyPort,
  });
}

function loadBrowserSessionId() {
  const filename = path.join(DATA_DIR, "browser-session-id");
  try {
    const existing = fs.readFileSync(filename, "utf8").trim();
    if (/^[a-f0-9]{32}$/.test(existing)) return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const id = crypto.randomBytes(16).toString("hex");
  fs.writeFileSync(filename, `${id}\n`, { encoding: "utf8", flag: "w" });
  return id;
}

const browserSessionId = loadBrowserSessionId();

function requestHostname(req) {
  if (PUBLIC_HOSTNAME) return PUBLIC_HOSTNAME;
  try {
    return new URL(`${PUBLIC_PROTOCOL}//${req.headers.host || "127.0.0.1"}`).hostname;
  } catch {
    return "127.0.0.1";
  }
}

function incomingHostname(req) {
  try {
    return new URL(`http://${req.headers.host || ""}`).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

function getServerInfo(req) {
  return {
    hostname: requestHostname(req),
    port: PUBLIC_PORT,
    crossDomainPort: PUBLIC_CROSS_PORT,
    protocol: PUBLIC_PROTOCOL,
  };
}

const logger = new RammerheadLogging({ logLevel: "warn" });
const proxy = new RammerheadProxy({
  logger,
  bindingAddress: HOST,
  port: PORT,
  crossDomainPort: CROSS_PORT,
  ssl: tlsOptions,
  getServerInfo,
  disableLocalStorageSync: false,
  disableHttp2: false,
  jsCache: new RammerheadJSMemCache(96 * 1024 * 1024),
});

const engineDiagnostic = {
  mainPort: PORT,
  crossPort: CROSS_PORT,
  tlsEnabled: TLS_ENABLED,
  publicProtocol: PUBLIC_PROTOCOL,
  publicHostname: PUBLIC_HOSTNAME,
  publicPort: PUBLIC_PORT,
  publicCrossPort: PUBLIC_CROSS_PORT,
};
if (TLS_ENABLED) {
  const serverCertificate = new crypto.X509Certificate(tlsOptions.cert);
  Object.assign(engineDiagnostic, {
    certificateSubject: serverCertificate.subject,
    certificateIssuer: serverCertificate.issuer,
    certificateValidFrom: serverCertificate.validFrom,
    certificateValidTo: serverCertificate.validTo,
    certificateFingerprint256: serverCertificate.fingerprint256,
    certificateSubjectAltName: serverCertificate.subjectAltName,
  });
}
diagnosticLog("engine_start", engineDiagnostic);
for (const [listener, port] of [[proxy.server1, PORT], [proxy.server2, CROSS_PORT]]) {
  if (TLS_ENABLED) {
    listener.on("tlsClientError", (error, socket) => {
      diagnosticLog("tls_client_error", {
        port,
        remoteAddress: truncateDiagnostic(socket && socket.remoteAddress, 100),
        code: truncateDiagnostic(error && error.code, 100),
        message: truncateDiagnostic(error && error.message, 500),
      });
    });
  }
  listener.on("clientError", (error, socket) => {
    diagnosticLog("http_client_error", {
      port,
      remoteAddress: truncateDiagnostic(socket && socket.remoteAddress, 100),
      code: truncateDiagnostic(error && error.code, 100),
      message: truncateDiagnostic(error && error.message, 500),
    });
  });
}

const sessionStore = new RammerheadSessionFileCache({
  logger,
  saveDirectory: sessionsDirectory,
  cacheTimeout: 1000 * 60 * 10,
  cacheCheckInterval: 1000 * 60 * 5,
  deleteUnused: false,
  deleteCorruptedSessions: true,
  staleCleanupOptions: {
    staleTimeout: 1000 * 60 * 60 * 24 * 30,
    maxToLive: null,
    staleCheckInterval: 1000 * 60 * 60 * 6,
  },
});
sessionStore.attachToProxy(proxy);

function ensureProxySession() {
  let session = sessionStore.get(browserSessionId, false);
  if (!session) {
    const freshSession = new RammerheadSession({
      id: browserSessionId,
      disableShuffling: true,
      prependScripts: ["/lan-toolbar.js"],
    });
    sessionStore.addSerializedSession(browserSessionId, freshSession.serializeSession());
    session = sessionStore.get(browserSessionId, false);
  }
  if (!session) throw new Error("Could not initialize the persistent browser session.");
  if (!session.injectable.scripts.includes("/lan-toolbar.js")) {
    session.injectable.scripts.unshift("/lan-toolbar.js");
  }
  // Stable paths avoid rewriting edge cases in large application bundles and
  // make cross-port session validation possible without sharing auth cookies
  // across two different browser origins.
  if (session.shuffleDict !== null) session.shuffleDict = null;
  session["lan-diagnostic"] = async (message) => {
    recordBrowserReport(message && message.report, "hammerhead_service_message", PORT);
    return { ok: true };
  };
  session.proxy = proxy;
  return session;
}

ensureProxySession();

function authSignature(sessionId) {
  return crypto.createHmac("sha256", ACCESS_TOKEN).update(`v1:${sessionId}`).digest("base64url");
}

function authCookieValue() {
  return `${browserSessionId}.${authSignature(browserSessionId)}`;
}

function constantTimeEqual(left, right) {
  const leftHash = crypto.createHash("sha256").update(String(left)).digest();
  const rightHash = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return "";
    }
  }
  return "";
}

function isAuthorized(req) {
  const value = readCookie(req, AUTH_COOKIE);
  const separator = value.indexOf(".");
  if (separator < 0) return false;
  const sessionId = value.slice(0, separator);
  const signature = value.slice(separator + 1);
  return sessionId === browserSessionId && constantTimeEqual(signature, authSignature(sessionId));
}

function securityHeaders(contentType) {
  return {
    "Cache-Control": "no-store",
    "Content-Type": contentType,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  };
}

function send(res, status, body, contentType = "text/plain; charset=utf-8", extraHeaders = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  res.writeHead(status, {
    ...securityHeaders(contentType),
    "Content-Length": String(payload.length),
    ...extraHeaders,
  });
  res.end(payload);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(303, {
    "Cache-Control": "no-store",
    Location: location,
    "Content-Length": "0",
    ...extraHeaders,
  });
  res.end();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function pageShell(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} · ${APP_NAME}</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; color: #eaf0ff; background: radial-gradient(circle at 50% -20%, #253765 0, #10182d 40%, #070b15 100%); }
    main { width: min(92vw, 660px); padding: 34px; border: 1px solid #314267; border-radius: 20px; background: rgba(13, 21, 40, .94); box-shadow: 0 24px 80px rgba(0,0,0,.45); }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
    .mark { display: grid; place-items: center; width: 42px; height: 42px; border-radius: 13px; background: linear-gradient(135deg, #67e8f9, #818cf8); color: #091225; font-size: 22px; font-weight: 900; }
    h1 { margin: 0; font-size: clamp(24px, 4vw, 34px); letter-spacing: -.03em; }
    p { color: #aebbd6; line-height: 1.55; }
    form { display: flex; gap: 10px; margin-top: 22px; }
    input, button { min-height: 48px; border-radius: 12px; font: inherit; }
    input { min-width: 0; flex: 1; padding: 0 15px; color: #111827; background: #fff; border: 2px solid transparent; outline: none; }
    input:focus { border-color: #67e8f9; box-shadow: 0 0 0 4px rgba(103,232,249,.15); }
    button { padding: 0 20px; border: 0; color: #07111f; background: linear-gradient(135deg, #67e8f9, #a5b4fc); font-weight: 800; cursor: pointer; }
    button:hover { filter: brightness(1.08); }
    .error { padding: 11px 13px; border: 1px solid #ef6c83; border-radius: 10px; color: #ffd8df; background: rgba(190,24,60,.18); }
    .notice { margin-top: 20px; padding: 12px 14px; border-radius: 11px; color: #bdd1ff; background: #17233e; font-size: 14px; }
    .actions { display: flex; justify-content: space-between; align-items: center; gap: 14px; margin-top: 24px; }
    .actions form { margin: 0; }
    .link-button { min-height: 38px; padding: 0 13px; color: #cbd5e1; background: #28344d; }
    code { color: #a5f3fc; }
    @media (max-width: 560px) { main { padding: 24px 18px; } form { flex-direction: column; } button { width: 100%; } }
  </style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function loginPage(showError) {
  return pageShell(
    "Unlock",
    `<div class="brand"><div class="mark">↗</div><h1>${APP_NAME}</h1></div>
     <p>Enter the private access token printed by the Python server.</p>
     ${showError ? '<p class="error" role="alert">That token is not valid. Please try again.</p>' : ""}
     <form method="post" action="/auth/login">
       <input name="token" type="password" aria-label="Access token" placeholder="Access token" autocomplete="current-password" autofocus required>
       <button type="submit">Unlock</button>
     </form>
     <div class="notice">Traffic is fetched by this laptop and rendered as a normal interactive page in your browser.</div>`,
  );
}

function homePage() {
  return pageShell(
    "Browse",
    `<div class="brand"><div class="mark">↗</div><h1>Browse through this laptop</h1></div>
     <p>Enter a web address or search phrase. The next page remains inside the authenticated proxy session.</p>
     <form method="get" action="/go">
       <input name="q" type="text" aria-label="Web address or search" placeholder="google.com or search the web" autocomplete="off" spellcheck="false" autofocus required>
       <button type="submit">Go</button>
     </form>
     <div class="notice" id="browser-security-status">Checking browser security context…</div>
     <script defer src="/lan-status.js"></script>
     <div class="actions"><span><code>HTTP/S</code> pages only</span><form method="post" action="/auth/logout"><button class="link-button" type="submit">Lock</button></form></div>`,
  );
}

async function readForm(req) {
  const declaredLength = Number(req.headers["content-length"] || "0");
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > MAX_FORM_BYTES) {
    throw new Error("Form is too large.");
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_FORM_BYTES) throw new Error("Form is too large.");
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

async function readDiagnosticJson(req) {
  const declaredLength = Number(req.headers["content-length"] || "0");
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > MAX_DIAGNOSTIC_BYTES) {
    throw new Error("Diagnostic report is too large.");
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_DIAGNOSTIC_BYTES) throw new Error("Diagnostic report is too large.");
    chunks.push(chunk);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid diagnostic report.");
  return parsed;
}

function normalizeAddress(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) throw new Error("Enter a web address or search phrase.");
  if (value.length > 4096) throw new Error("That address is too long.");

  let candidate = value;
  const looksLikeSearch = /\s/.test(value) || (!value.includes(".") && !value.includes(":") && !value.startsWith("localhost"));
  if (looksLikeSearch) {
    candidate = `https://duckduckgo.com/?q=${encodeURIComponent(value)}`;
  } else if (value.startsWith("//")) {
    candidate = `https:${value}`;
  } else if (!/^[a-z][a-z\d+.-]*:\/\//i.test(value)) {
    candidate = `https://${value}`;
  }

  const target = new URL(candidate);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error("Only HTTP and HTTPS addresses are supported.");
  if (!target.hostname || target.username || target.password) throw new Error("That address is not allowed.");
  return target.toString();
}

const failedLogins = new Map();

function loginIsRateLimited(ip) {
  const now = Date.now();
  const recent = (failedLogins.get(ip) || []).filter((timestamp) => now - timestamp < 5 * 60 * 1000);
  failedLogins.set(ip, recent);
  return recent.length >= 8;
}

function recordFailedLogin(ip) {
  const attempts = failedLogins.get(ip) || [];
  attempts.push(Date.now());
  failedLogins.set(ip, attempts);
}

function loginClientAddress(req) {
  const socketAddress = (req.socket.remoteAddress || "unknown").toLowerCase();
  const socketIsLoopback = socketAddress === "127.0.0.1" || socketAddress === "::1" || socketAddress === "::ffff:127.0.0.1";
  if (!PUBLIC_HOSTNAME || !socketIsLoopback) return socketAddress;

  const forwarded = Array.isArray(req.headers["x-forwarded-for"])
    ? req.headers["x-forwarded-for"][0]
    : req.headers["x-forwarded-for"];
  const candidate = String(forwarded || "").split(",", 1)[0].trim();
  return net.isIP(candidate) ? candidate : socketAddress;
}

function authorizedCookieHeader() {
  const secure = PUBLIC_PROTOCOL === "https:" ? "; Secure" : "";
  return `${AUTH_COOKIE}=${encodeURIComponent(authCookieValue())}; Path=/; HttpOnly${secure}; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE_SECONDS}`;
}

function clearCookieHeader() {
  const secure = PUBLIC_PROTOCOL === "https:" ? "; Secure" : "";
  return `${AUTH_COOKIE}=; Path=/; HttpOnly${secure}; SameSite=Strict; Max-Age=0`;
}

function pathnameOf(req) {
  try {
    return new URL(req.url, "http://proxy.invalid").pathname;
  } catch {
    return "/";
  }
}

function allowUnauthenticated(req) {
  const pathname = pathnameOf(req);
  if (pathname === "/" || pathname === "/auth/login" || pathname === "/healthz" || pathname === "/favicon.svg" || pathname === "/__control/shutdown") return true;
  if (req.method === "OPTIONS" && pathname === "/messaging") {
    try {
      const origin = new URL(req.headers.origin || "");
      const originPort = origin.port || (origin.protocol === "https:" ? "443" : "80");
      return origin.protocol === PUBLIC_PROTOCOL &&
        origin.hostname === requestHostname(req) &&
        [String(PUBLIC_PORT), String(PUBLIC_CROSS_PORT)].includes(originPort);
    } catch {
      return false;
    }
  }
  return false;
}

function isAuthorizedCrossPortRequest(req) {
  if (Number(req.socket.localPort) !== CROSS_PORT) return false;
  const parsed = urlUtils.parseProxyUrl(req.url || "");
  if (!parsed || parsed.sessionId !== browserSessionId) return false;
  return Boolean(sessionStore.get(browserSessionId, false));
}

function rejectUnauthorized(req, res, isWebsocket) {
  const parsed = urlUtils.parseProxyUrl(req.url || "");
  diagnosticLog("authentication_rejected", {
    method: truncateDiagnostic(req.method, 20),
    path: truncateDiagnostic(pathnameOf(req), 500),
    destination: parsed ? safeDiagnosticUrl(parsed.destUrl) : "",
    proxyPort: req.socket.localPort,
    websocket: Boolean(isWebsocket),
    cookiePresent: Boolean(readCookie(req, AUTH_COOKIE)),
  });
  if (isWebsocket) {
    res.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  } else {
    send(res, 401, "Authentication required. Return to the proxy home page.\n");
  }
}

proxy.addToOnRequestPipeline((req, res, _serverInfo, _isRoute, isWebsocket) => {
  const pathname = pathnameOf(req);
  if (PUBLIC_HOSTNAME && !["/healthz", "/__control/shutdown"].includes(pathname) && incomingHostname(req) !== PUBLIC_HOSTNAME) {
    if (isWebsocket) {
      res.end("HTTP/1.1 421 Misdirected Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    } else {
      send(res, 421, "Request hostname does not match the configured public hostname.\n");
    }
    return true;
  }
  if (allowUnauthenticated(req) || isAuthorized(req) || isAuthorizedCrossPortRequest(req)) return false;
  rejectUnauthorized(req, res, isWebsocket);
  return true;
});

// Current Chromium advertises zstd, but Hammerhead 31.x can only decode and
// re-encode gzip, deflate, and Brotli. Passing zstd through HTML rewriting
// corrupts the response and Chrome reports ERR_CONTENT_DECODING_FAILED (seen
// on Instagram). Limit destination negotiation to supported encodings.
proxy.addToOnRequestPipeline((req, _res, _serverInfo, isRoute, isWebsocket) => {
  if (!isRoute && !isWebsocket) req.headers["accept-encoding"] = "gzip, deflate, br";
  return false;
}, true);

const dnsSafetyCache = new Map();

function isPrivateIp(address) {
  if (net.isIPv4(address)) {
    const octets = address.split(".").map(Number);
    return (
      octets[0] === 0 ||
      octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
      octets[0] >= 224
    );
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    if (normalized.startsWith("::ffff:")) return isPrivateIp(normalized.slice(7));
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || /^fe[89ab]/.test(normalized);
  }
  return true;
}

async function destinationIsPrivate(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local")) return true;
  if (net.isIP(normalized)) return isPrivateIp(normalized);

  const cached = dnsSafetyCache.get(normalized);
  if (cached && cached.expires > Date.now()) return cached.private;

  try {
    const addresses = await dns.lookup(normalized, { all: true, verbatim: true });
    const isPrivate = addresses.length === 0 || addresses.some(({ address }) => isPrivateIp(address));
    dnsSafetyCache.set(normalized, { private: isPrivate, expires: Date.now() + 60_000 });
    return isPrivate;
  } catch {
    return false;
  }
}

proxy.addToOnRequestPipeline(
  async (req, res, _serverInfo, isRoute, isWebsocket) => {
    if (ALLOW_PRIVATE_TARGETS || isRoute) return false;
    const parsed = urlUtils.parseProxyUrl(req.url || "");
    if (!parsed || !(await destinationIsPrivate(parsed.destResourceInfo.hostname))) return false;
    if (isWebsocket) {
      res.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    } else {
      send(res, 403, "Private and local destination addresses are blocked.\n");
    }
    return true;
  },
  true,
);

let diagnosticRequestCounter = 0;
proxy.addToOnRequestPipeline(
  (req, res, _serverInfo, isRoute, isWebsocket) => {
    if (isRoute || isWebsocket) return false;
    const parsed = urlUtils.parseProxyUrl(req.url || "");
    if (!parsed || !isInstagramFamilyUrl(parsed.destUrl)) return false;

    const requestId = `${Date.now().toString(36)}-${(++diagnosticRequestCounter).toString(36)}`;
    const started = Date.now();
    let responseLogged = false;
    diagnosticLog("instagram_request", {
      requestId,
      method: truncateDiagnostic(req.method, 20),
      url: safeDiagnosticUrl(parsed.destUrl),
      proxyPort: req.socket.localPort,
      crossPort: Number(req.socket.localPort) === CROSS_PORT,
      secFetchSite: truncateDiagnostic(req.headers["sec-fetch-site"], 80),
      secFetchMode: truncateDiagnostic(req.headers["sec-fetch-mode"], 80),
      secFetchDest: truncateDiagnostic(req.headers["sec-fetch-dest"], 80),
      origin: safeDiagnosticUrl(req.headers.origin || ""),
      referer: safeDiagnosticUrl(req.headers.referer || ""),
    });

    const originalWriteHead = res.writeHead;
    res.writeHead = function (statusCode, ...args) {
      const contentType = headerFromWriteHeadArgs(args, "content-type");
      const contentEncoding = headerFromWriteHeadArgs(args, "content-encoding");
      const allowOrigin = headerFromWriteHeadArgs(args, "access-control-allow-origin");
      const responseLocation = headerFromWriteHeadArgs(args, "location");
      const result = originalWriteHead.call(this, statusCode, ...args);
      if (!responseLogged) {
        responseLogged = true;
        diagnosticLog("instagram_response", {
          requestId,
          url: safeDiagnosticUrl(parsed.destUrl),
          statusCode: Number(statusCode),
          durationMs: Date.now() - started,
          contentType: truncateDiagnostic(contentType || this.getHeader("content-type"), 200),
          contentEncoding: truncateDiagnostic(contentEncoding || this.getHeader("content-encoding"), 80),
          accessControlAllowOrigin: truncateDiagnostic(allowOrigin || this.getHeader("access-control-allow-origin"), 300),
          location: safeDiagnosticUrl(responseLocation || this.getHeader("location") || ""),
        });
      }
      return result;
    };
    res.once("close", () => {
      if (!responseLogged) {
        diagnosticLog("instagram_connection_closed", {
          requestId,
          url: safeDiagnosticUrl(parsed.destUrl),
          durationMs: Date.now() - started,
        });
      }
    });
    return false;
  },
  true,
);

proxy.GET("/", (req, res) => {
  const query = new URL(req.url, "http://proxy.invalid").searchParams;
  send(res, 200, isAuthorized(req) ? homePage() : loginPage(query.get("error") === "1"), "text/html; charset=utf-8");
});

proxy.POST("/auth/login", async (req, res) => {
  const ip = loginClientAddress(req);
  if (loginIsRateLimited(ip)) {
    send(res, 429, "Too many failed attempts. Try again in a few minutes.\n", "text/plain; charset=utf-8", { "Retry-After": "300" });
    return;
  }
  try {
    const form = await readForm(req);
    if (!constantTimeEqual(form.get("token") || "", ACCESS_TOKEN)) {
      recordFailedLogin(ip);
      redirect(res, "/?error=1");
      return;
    }
    failedLogins.delete(ip);
    ensureProxySession();
    redirect(res, "/", { "Set-Cookie": authorizedCookieHeader() });
  } catch (error) {
    send(res, 400, `${error.message}\n`);
  }
});

proxy.POST("/auth/logout", (req, res) => {
  redirect(res, "/", { "Set-Cookie": clearCookieHeader() });
});

proxy.GET("/go", (req, res) => {
  try {
    const query = new URL(req.url, "http://proxy.invalid").searchParams;
    const target = normalizeAddress(query.get("q"));
    const session = ensureProxySession();
    const info = getServerInfo(req);
    const proxyUrl = urlUtils.getProxyUrl(target, {
      proxyHostname: info.hostname,
      proxyPort: String(info.port),
      proxyProtocol: info.protocol,
      sessionId: session.id,
      windowId: session.options.windowId,
    });
    redirect(res, proxyUrl);
  } catch (error) {
    send(res, 400, pageShell("Invalid address", `<div class="brand"><div class="mark">!</div><h1>Cannot open that address</h1></div><p class="error">${escapeHtml(error.message)}</p><p><a href="/" style="color:#a5f3fc">Return to the address bar</a></p>`), "text/html; charset=utf-8");
  }
});

proxy.GET("/healthz", (_req, res) => {
  send(res, 200, "ok\n");
});

proxy.POST("/__diagnostics/client", async (req, res) => {
  try {
    const report = await readDiagnosticJson(req);
    recordBrowserReport(report, "direct_http", req.socket.localPort);
    send(res, 204, "");
  } catch (error) {
    send(res, 400, `${error.message}\n`);
  }
});

proxy.POST("/__control/shutdown", (req, res) => {
  const remoteAddress = (req.socket.remoteAddress || "").toLowerCase();
  const isLoopback = remoteAddress === "127.0.0.1" || remoteAddress === "::1" || remoteAddress === "::ffff:127.0.0.1";
  const providedToken = req.headers["x-lan-proxy-control"] || "";
  if (!isLoopback || !constantTimeEqual(providedToken, CONTROL_TOKEN)) {
    send(res, 404, "Not found.\n");
    return;
  }
  send(res, 202, "Stopping.\n");
  setImmediate(() => shutdown("Python launcher request"));
});

const favicon = Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#111b33"/><path d="M18 45 45 18m0 0H25m20 0v20" fill="none" stroke="#67e8f9" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
);
proxy.GET("/favicon.svg", { content: favicon, contentType: "image/svg+xml" });

const homeStatusScript = String.raw`(() => {
  const status = document.getElementById("browser-security-status");
  const secure = window.isSecureContext === true;
  const serviceWorkerAvailable = "serviceWorker" in navigator;
  if (status) {
    status.textContent = secure
      ? "Secure browser context is active. Secure-only browser APIs are available."
      : "WARNING: this browser does not trust the HTTPS context. Reinstall the root CA under Trusted Authorities, restart the browser, and do not bypass the warning page.";
    status.style.color = secure ? "#b7f7d5" : "#ffd2d9";
    status.style.background = secure ? "#123628" : "#481b27";
  }
  try {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/__diagnostics/client", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify({
      type: "proxy_home_environment",
      page: location.href,
      isSecureContext: secure,
      serviceWorkerAvailable,
      cookieEnabled: navigator.cookieEnabled,
      userAgent: navigator.userAgent
    }));
  } catch (_) {}
})();`;

proxy.GET("/lan-status.js", {
  content: Buffer.from(homeStatusScript, "utf8"),
  contentType: "application/javascript; charset=utf-8",
});

const toolbarScript = String.raw`(() => {
  if (window !== window.top || window.__lanProxyToolbarInstalled) return;
  window.__lanProxyToolbarInstalled = true;

  const hammerhead = window["%hammerhead%"];
  const destinationUrl = () => {
    try {
      return hammerhead && hammerhead.utils && hammerhead.utils.url
        ? hammerhead.utils.url.getDestinationUrl(String(window.location.href))
        : String(window.location.href);
    } catch (_) {
      return String(window.location.href);
    }
  };

  const safeClientUrl = (value) => {
    try {
      const parsed = new URL(String(value || ""));
      return parsed.protocol + "//" + parsed.host + parsed.pathname;
    } catch (_) {
      return String(value || "").slice(0, 300);
    }
  };

  const reported = new Set();
  const report = (type, details = {}) => {
    try {
      const payload = {
        type,
        page: safeClientUrl(destinationUrl()),
        ...details
      };
      const key = type + "|" + (payload.message || payload.resource || payload.source || "");
      if (reported.has(key) || reported.size >= 120 || !hammerhead) return;
      reported.add(key);
      if (hammerhead.createNativeXHR) {
        const xhr = hammerhead.createNativeXHR();
        xhr.open("POST", "/__diagnostics/client", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify(payload));
        return;
      }
      if (hammerhead.transport && hammerhead.transport.asyncServiceMsg) {
        const pending = hammerhead.transport.asyncServiceMsg({ cmd: "lan-diagnostic", report: payload });
        if (pending && typeof pending.catch === "function") pending.catch(() => {});
      }
    } catch (_) {}
  };

  try {
    if (hammerhead && hammerhead.on && hammerhead.EVENTS && hammerhead.EVENTS.consoleMethCalled) {
      hammerhead.on(hammerhead.EVENTS.consoleMethCalled, (event) => {
        const method = String(event && event.meth || "").toLowerCase();
        if (method === "error" || method === "warn") {
          report("console_message", {
            message: (method + ": " + String(event && event.line || "")).slice(0, 1000)
          });
        }
      });
    }
  } catch (_) {}

  window.addEventListener("error", (event) => {
    const target = event.target;
    if (target && target !== window) {
      const resource = target.currentSrc || target.src || target.href || "";
      report("resource_error", {
        tag: String(target.tagName || "").slice(0, 80),
        resource: safeClientUrl(resource),
        message: "A page resource failed to load"
      });
      return;
    }
    report("javascript_error", {
      message: String(event.message || "Unknown JavaScript error").slice(0, 1000),
      source: safeClientUrl(event.filename || ""),
      line: Number(event.lineno) || 0,
      column: Number(event.colno) || 0
    });
  }, true);
  window.addEventListener("unhandledrejection", (event) => {
    let message = "Unhandled promise rejection";
    try { message = String(event.reason && (event.reason.message || event.reason) || message); } catch (_) {}
    report("unhandled_rejection", { message: message.slice(0, 1000) });
  });
  document.addEventListener("securitypolicyviolation", (event) => {
    report("content_security_policy", {
      message: String(event.violatedDirective || "CSP violation").slice(0, 500),
      resource: safeClientUrl(event.blockedURI || "")
    });
  });

  const normalize = (raw) => {
    const value = String(raw || "").trim();
    if (!value) return null;
    if (/\s/.test(value) || (!value.includes(".") && !value.includes(":") && !value.startsWith("localhost"))) {
      return "https://duckduckgo.com/?q=" + encodeURIComponent(value);
    }
    if (value.startsWith("//")) return "https:" + value;
    if (!/^[a-z][a-z\d+.-]*:\/\//i.test(value)) return "https://" + value;
    if (!/^https?:\/\//i.test(value)) return "https://duckduckgo.com/?q=" + encodeURIComponent(value);
    return value;
  };

  const install = () => {
    if (!document.documentElement || document.getElementById("lan-proxy-toolbar-host")) return;
    const host = document.createElement("div");
    host.id = "lan-proxy-toolbar-host";
    host.setAttribute("data-lan-proxy-ui", "true");
    host.style.cssText = "all:initial!important;position:fixed!important;right:10px!important;bottom:10px!important;width:auto!important;height:auto!important;display:block!important;z-index:2147483647!important;color-scheme:dark!important;pointer-events:none!important";
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = [
      '<style>',
      '*{box-sizing:border-box}.wrap{pointer-events:auto;display:flex;flex-direction:column;align-items:flex-end;gap:7px;font:13px/1.2 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#eaf0ff}.toggle{height:38px!important;border-radius:999px!important;border:1px solid #51617e!important;background:#10182d!important;color:#a5f3fc!important;font-weight:800!important;box-shadow:0 4px 18px rgba(0,0,0,.38)!important}.bar{width:min(570px,calc(100vw - 20px));height:48px;display:flex;align-items:center;gap:7px;padding:6px 9px;background:#10182d;border:1px solid #344361;border-radius:13px;box-shadow:0 5px 22px rgba(0,0,0,.38)}.bar[hidden]{display:none!important}',
      'button,input{height:35px;border-radius:9px;font:inherit}button{min-width:35px;padding:0 10px;border:1px solid #425272;background:#24314b;color:#f2f6ff;cursor:pointer}button:hover{background:#31415f}form{display:flex;flex:1;gap:7px;margin:0}input{min-width:0;flex:1;padding:0 12px;border:1px solid #52617d;outline:none;background:#fff;color:#111827}input:focus{border-color:#67e8f9;box-shadow:0 0 0 2px rgba(103,232,249,.25)}.go{border:0;background:#67e8f9;color:#07111f;font-weight:800}.badge{white-space:nowrap;color:#a5f3fc;font-weight:700}.dot{display:inline-block;width:7px;height:7px;margin-right:6px;border-radius:50%;background:#34d399;box-shadow:0 0 8px #34d399}@media(max-width:620px){.bar{gap:4px;padding:6px}.badge{font-size:0}.badge:after{content:"Proxy";font-size:11px}button{padding:0 8px}.go{display:none}}',
      '</style>',
      '<div class="wrap"><div class="bar" role="navigation" aria-label="LAN proxy controls" hidden>',
      '<span class="badge" title="This page is travelling through the laptop"><span class="dot"></span>LAN Proxy</span>',
      '<button type="button" data-action="back" title="Back" aria-label="Back">←</button>',
      '<button type="button" data-action="forward" title="Forward" aria-label="Forward">→</button>',
      '<button type="button" data-action="reload" title="Reload" aria-label="Reload">↻</button>',
      '<form><input aria-label="Web address or search" autocomplete="off" spellcheck="false"><button class="go" type="submit">Go</button></form>',
      '<button type="button" data-action="close" title="Collapse" aria-label="Collapse">×</button>',
      '</div><button class="toggle" type="button" aria-expanded="false"><span class="dot"></span>LAN Proxy</button></div>'
    ].join('');
    const input = root.querySelector("input");
    const bar = root.querySelector(".bar");
    const toggle = root.querySelector(".toggle");
    input.value = destinationUrl();
    toggle.addEventListener("click", () => {
      bar.hidden = false;
      toggle.hidden = true;
      toggle.setAttribute("aria-expanded", "true");
      input.focus();
    });
    root.querySelector('[data-action="close"]').addEventListener("click", () => {
      bar.hidden = true;
      toggle.hidden = false;
      toggle.setAttribute("aria-expanded", "false");
    });
    root.querySelector('[data-action="back"]').addEventListener("click", () => history.back());
    root.querySelector('[data-action="forward"]').addEventListener("click", () => history.forward());
    root.querySelector('[data-action="reload"]').addEventListener("click", () => location.reload());
    root.querySelector("form").addEventListener("submit", (event) => {
      event.preventDefault();
      const next = normalize(input.value);
      if (next) {
        const proxyNext = hammerhead && hammerhead.utils && hammerhead.utils.url
          ? hammerhead.utils.url.getProxyUrl(next)
          : next;
        window.location.assign(proxyNext);
      }
    });
    const wrap = root.querySelector(".wrap");
    for (const eventName of ["click", "dblclick", "mousedown", "mouseup", "pointerdown", "pointerup", "keydown", "keyup", "keypress", "wheel"]) {
      wrap.addEventListener(eventName, (event) => event.stopPropagation());
    }
    document.documentElement.appendChild(host);
    report("target_environment", {
      isSecureContext: window.isSecureContext === true,
      serviceWorkerAvailable: "serviceWorker" in navigator,
      cookieEnabled: navigator.cookieEnabled,
      userAgent: navigator.userAgent
    });
    setInterval(() => {
      if (!input.matches(":focus")) input.value = destinationUrl();
      if (!host.isConnected && document.documentElement) document.documentElement.appendChild(host);
    }, 1000);
  };

  if (document.documentElement) install();
  else document.addEventListener("DOMContentLoaded", install, { once: true });
})();`;

proxy.GET("/lan-toolbar.js", {
  content: Buffer.from(toolbarScript, "utf8"),
  contentType: "application/javascript; charset=utf-8",
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${APP_NAME}: received ${signal}; saving the browser session and stopping.`);
  try {
    proxy.close();
  } finally {
    diagnosticStream.end();
    setTimeout(() => process.exit(0), 100).unref();
  }
}

process.on("SIGINT", () => shutdown("Ctrl+C"));
process.on("SIGBREAK", () => shutdown("Ctrl+Break"));
process.on("SIGTERM", () => shutdown("termination request"));
process.on("uncaughtException", (error) => {
  console.error(`${APP_NAME}: fatal error:`, error);
  try { proxy.close(); } catch (_) {}
  process.exit(1);
});
process.on("unhandledRejection", (error) => {
  console.error(`${APP_NAME}: unhandled error:`, error);
});

console.log(`${APP_NAME} ${TLS_ENABLED ? "HTTPS" : "HTTP"} engine is listening on ${HOST}:${PORT} (cross-domain port ${CROSS_PORT}).`);
if (PORT !== PUBLIC_PORT || CROSS_PORT !== PUBLIC_CROSS_PORT || (TLS_ENABLED ? "https:" : "http:") !== PUBLIC_PROTOCOL) {
  console.log(`Public origin mode: ${PUBLIC_PROTOCOL}//${PUBLIC_HOSTNAME || "<request-host>"}:${PUBLIC_PORT} (cross-origin port ${PUBLIC_CROSS_PORT}).`);
}
console.log(`Target pages are real rewritten HTML/JS; no browser or screenshot streamer is running.`);
console.log(`Diagnostic log: ${diagnosticLogPath}`);
if (ALLOW_PRIVATE_TARGETS) console.warn("WARNING: private target addresses are enabled for testing.");
