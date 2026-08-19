# LAN Web Proxy

[![CI](https://github.com/Mhrnqaruni/lan-web-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Mhrnqaruni/lan-web-proxy/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An authenticated, self-hosted browser proxy that loads real interactive web
pages through another computer or VPS. It rewrites HTML, JavaScript, requests,
cookies, storage, navigation, forms, and WebSockets using
[Rammerhead](https://github.com/binary-person/rammerhead) and
[TestCafe Hammerhead](https://github.com/DevExpress/testcafe-hammerhead).

It is not a screenshot or video stream, does not open a hidden browser on the
server, and does not require Docker.

> [!IMPORTANT]
> Use this only on systems, accounts, and networks you own or are authorized to
> access. This is not an anonymity service: websites normally see the public or
> VPN egress IP of the machine running the proxy.

## What it provides

- A simple login page protected by a private access token.
- A URL/search box followed by real, interactive proxied pages in the same tab.
- Persistent cookies, local storage, cache, navigation, fetch/XHR, forms, and
  WebSocket support where the destination site permits them.
- Trusted HTTPS on a local network through a generated local root certificate.
- Trusted public HTTPS on a VPS through a standard Caddy or Nginx reverse proxy.
- Private-address destination blocking by default, login rate limiting, secure
  authentication cookies, and redacted diagnostic logs.
- Windows and Linux support with ordinary Python and Node.js processes.

## Choose a mode

| Goal | Command | Public entry point | Certificate |
| --- | --- | --- | --- |
| Use another device on the same LAN | `python proxy_server.py` | Laptop LAN IP on ports `8080`/`8443` | Install the generated local CA once |
| Use a public VPS/domain | `python proxy_server.py --vps ...` | Your domain on HTTPS port `443` | Caddy/Nginx obtains a public certificate |

## Requirements

- Python 3.10 or newer
- Node.js 20 or newer, including `npm`
- A browser on the client device
- For VPS mode: a DNS hostname pointing to the VPS and Caddy or Nginx

## Quick start: another device on your LAN

### 1. Download and install

```powershell
git clone https://github.com/Mhrnqaruni/lan-web-proxy.git
cd lan-web-proxy
python -m pip install -r requirements.txt
npm ci --omit=dev --ignore-scripts
```

### 2. Start the proxy

```powershell
python .\proxy_server.py
```

The first run prepares the browser-rewriting assets. The terminal then prints:

- the access token;
- the setup address, such as `http://192.168.1.20:8080/`;
- the secure proxy address, such as `https://192.168.1.20:8443/`;
- the public certificate path and SHA-256 fingerprint.

### 3. Set up the other device

1. Open the printed `http://LAPTOP-IP:8080/` address on the other device.
2. Download the public root certificate.
3. Import it under **Trusted Authorities / Certificate Authorities**, enable
   website trust if asked, and compare its fingerprint with the laptop terminal.
4. Fully close and reopen the browser.
5. Open the printed `https://LAPTOP-IP:8443/` address.
6. Enter the token from the laptop terminal, then enter a URL or search phrase.

The browser cannot silently trust a new certificate. Never copy or install the
private key named `lan-proxy-root-ca-key.pem` on another device.

If Windows Firewall does not prompt, run PowerShell as Administrator once:

```powershell
New-NetFirewallRule -DisplayName "LAN Web Proxy" -Direction Inbound -Protocol TCP -LocalPort 8080,8443,8444 -Action Allow -Profile Private -RemoteAddress LocalSubnet
```

See [the detailed LAN guide](docs/LAN.md) for Linux and browser-specific
certificate instructions.

## Quick start: public VPS with Caddy

The safe VPS layout is:

```text
Browser ──HTTPS──> Caddy :443 ──HTTP on loopback──> Proxy :8080 ──HTTPS──> Website
```

Only Caddy is public. The Python-launched backend stays on `127.0.0.1`.

### 1. Prepare DNS and the VPS

Create an `A`/`AAAA` DNS record such as `proxy.example.com` pointing to your
VPS. Allow inbound TCP ports `80` and `443`. Install Python 3.10+, Node.js 20+,
Git, and [Caddy](https://caddyserver.com/docs/install).

### 2. Install the application

```bash
git clone https://github.com/Mhrnqaruni/lan-web-proxy.git
cd lan-web-proxy
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
npm ci --omit=dev --ignore-scripts
```

Generate a private token and save it somewhere secure:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
export LAN_PROXY_ACCESS_TOKEN='paste-the-generated-token-here'
```

### 3. Start the private backend

Replace the hostname below with your real DNS name:

```bash
python3 proxy_server.py --vps --public-hostname proxy.example.com
```

VPS mode requires a token of at least 16 characters and hides it from service
logs. It listens on `127.0.0.1:8080` by default.

### 4. Put Caddy in front

Create `/etc/caddy/Caddyfile`:

```caddyfile
proxy.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Validate and reload Caddy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Open `https://proxy.example.com/` and enter the token. Caddy obtains and renews
the publicly trusted certificate automatically when DNS is correct and ports
80/443 are reachable. No local CA installation is used in VPS mode.

For automatic startup, service hardening, updates, and Nginx configuration, use
the [complete VPS deployment guide](docs/VPS.md).

## Command-line options

```text
--vps                     Run behind an HTTPS reverse proxy
--public-hostname HOST    Required public DNS hostname in VPS mode
--public-port PORT        External HTTPS port (default: 443)
--host ADDRESS            Bind address (LAN: 0.0.0.0, VPS: 127.0.0.1)
--port PORT               LAN setup page or VPS backend (default: 8080)
--tls-port PORT           LAN HTTPS proxy (default: 8443)
--cross-port PORT         Internal cross-domain listener (default: main + 1)
--access-token TOKEN      Login token; VPS can use LAN_PROXY_ACCESS_TOKEN instead
```

Examples:

```powershell
# LAN with a stable token and custom ports
python .\proxy_server.py --access-token "a-long-private-token" --port 8090 --tls-port 9443 --cross-port 9444
```

```bash
# VPS with a nonstandard public HTTPS port
LAN_PROXY_ACCESS_TOKEN='a-very-long-private-token' python3 proxy_server.py \
  --vps --public-hostname proxy.example.com --public-port 8443
```

## Data, privacy, and diagnostics

Runtime state is stored under `.proxy_data/` and excluded from Git. It contains
site cookies/storage, session identifiers, generated certificates, private
keys, and redacted JSONL diagnostics. Treat the whole directory as sensitive.

Each run prints its diagnostic-log path. Logs include request paths and status
codes for selected compatibility failures, TLS errors, browser console errors,
and capability information. They exclude cookies, request bodies, passwords,
and URL query values. Review a log before sharing it.

To reset all browsing sessions, stop the proxy and move `.proxy_data/` to a
private backup. In LAN mode this also creates a new root CA, which must then be
installed again on client devices.

## Compatibility limits

This project handles many modern sites, including the compression and secure-
context behavior needed by large JavaScript applications. However, no URL-
rewriting proxy can perfectly reproduce every origin-bound browser feature.
Passkeys/WebAuthn, DRM media, some OAuth or anti-bot flows, nested service
workers, WebRTC, and sites that explicitly reject rewritten origins may fail.

Do not report a site merely blocking a proxy as a security vulnerability. For
reproducible application failures, include the browser/version, destination
hostname, exact error, and a redacted diagnostic log in a bug report.

## Development

```bash
python -m pip install -r requirements.txt
npm ci --ignore-scripts
npm run prepare-engine
python -m unittest discover -s tests -v
python -m py_compile proxy_server.py
npm run check
```

The dependency install uses a lockfile. `prepare_engine.js` applies the small,
deterministic Rammerhead compatibility patches and rebuilds its client assets
from the exact installed Hammerhead version. `vendor/ip` is a deliberately
minimal `toBuffer()` compatibility shim for Rammerhead's unused clustering
dependency; it replaces an upstream package with no patched release for
[GHSA-2p57-rm9w-gvfp](https://github.com/advisories/GHSA-2p57-rm9w-gvfp).

## Security

Read [SECURITY.md](SECURITY.md) before exposing the application publicly. Keep
the backend loopback-only in VPS mode, use a unique random token, run under an
unprivileged account, update dependencies regularly, and never commit runtime
data or secrets.

## License and upstream projects

This repository is available under the [MIT License](LICENSE). It builds on the
MIT-licensed [Rammerhead](https://github.com/binary-person/rammerhead) and
[TestCafe Hammerhead](https://github.com/DevExpress/testcafe-hammerhead)
projects; their respective copyrights remain with their authors.
