#!/usr/bin/env python3
"""Start the authenticated Rammerhead browser proxy without Docker."""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


APP_NAME = "LAN Web Proxy"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / ".proxy_data"
CERT_DIR = DATA_DIR / "certificates"


def validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be a number") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def validate_hostname(value: str) -> str:
    hostname = value.strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname):
        raise argparse.ArgumentTypeError("enter a DNS hostname such as proxy.example.com")
    return hostname


def restrict_private_file(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)


def discover_lan_addresses() -> list[str]:
    addresses: set[str] = set()
    default_address = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
            route_probe.connect(("8.8.8.8", 80))
            default_address = route_probe.getsockname()[0]
            addresses.add(default_address)
    except OSError:
        pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(item[4][0])
    except socket.gaierror:
        pass

    usable = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_private and not parsed.is_loopback and not parsed.is_link_local:
            usable.append(address)
    return sorted(set(usable), key=lambda address: (0 if address == default_address else 1, address))


def ensure_node_dependencies(node: str) -> None:
    engine = ROOT / "proxy_engine.js"
    package_lock = ROOT / "package-lock.json"
    installed = ROOT / "node_modules" / "rammerhead" / "package.json"
    if not engine.is_file():
        raise SystemExit(f"Missing proxy engine: {engine}")
    if not installed.is_file():
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm or not package_lock.is_file():
            raise SystemExit("Node dependencies are missing. Install Node.js, then run: npm install --ignore-scripts")
        print("Installing the proxy engine dependencies for the first run…", flush=True)
        result = subprocess.run([npm, "ci", "--omit=dev", "--ignore-scripts"], cwd=ROOT, check=False)
        if result.returncode:
            raise SystemExit("Could not install the Node proxy dependencies.")

    preparation = subprocess.run([node, str(ROOT / "prepare_engine.js")], cwd=ROOT, check=False)
    if preparation.returncode:
        raise SystemExit("Could not prepare the browser rewriting engine.")


def ensure_certificates(addresses: list[str], bind_host: str) -> tuple[Path, Path, Path, Path, str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as error:
        raise SystemExit(
            "Missing Python package 'cryptography'. Install it with:\n"
            "  python -m pip install -r requirements.txt"
        ) from error

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    root_cert_path = CERT_DIR / "lan-proxy-root-ca.crt"
    root_key_path = CERT_DIR / "lan-proxy-root-ca-key.pem"
    server_cert_path = CERT_DIR / "lan-proxy-server.crt"
    server_key_path = CERT_DIR / "lan-proxy-server-key.pem"

    if root_cert_path.is_file() and root_key_path.is_file():
        try:
            root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
            root_key = serialization.load_pem_private_key(root_key_path.read_bytes(), password=None)
        except (ValueError, TypeError) as error:
            raise SystemExit(f"The existing local CA is unreadable: {error}") from error
    else:
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LAN Web Proxy (local only)"),
                x509.NameAttribute(NameOID.COMMON_NAME, "LAN Web Proxy Local Root CA"),
            ]
        )
        now = datetime.now(UTC)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        root_key_path.write_bytes(
            root_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        root_cert_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

    ip_names = {ipaddress.ip_address("127.0.0.1")}
    for value in addresses + ([bind_host] if bind_host not in {"0.0.0.0", "::"} else []):
        try:
            ip_names.add(ipaddress.ip_address(value))
        except ValueError:
            pass
    dns_names = {"localhost", socket.gethostname()}
    san_names = [x509.IPAddress(value) for value in sorted(ip_names, key=str)]
    san_names.extend(x509.DNSName(value) for value in sorted(dns_names) if value)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAN Web Proxy")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(root_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    restrict_private_file(root_key_path)
    restrict_private_file(server_key_path)

    fingerprint = hashlib.sha256(root_cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    fingerprint = ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2))
    return root_cert_path, root_key_path, server_cert_path, server_key_path, fingerprint


class BootstrapHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_bootstrap_handler(
    root_cert_path: Path,
    tls_port: int,
    fingerprint: str,
    certificate_hosts: set[str],
):
    certificate = root_cert_path.read_bytes()

    class BootstrapHandler(BaseHTTPRequestHandler):
        server_version = "LANProxySetup/1.0"

        def log_message(self, format_string: str, *args: object) -> None:
            print(f"Setup page: {self.address_string()} - {format_string % args}")

        def request_host(self) -> str:
            try:
                candidate = urlsplit("//" + self.headers.get("Host", "")).hostname or "127.0.0.1"
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", candidate):
                    return candidate
                return "127.0.0.1"

        def send_bytes(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path in {"/lan-proxy-root-ca.crt", "/lan-proxy-root-ca.pem"}:
                self.send_bytes(
                    200,
                    certificate,
                    "application/x-x509-ca-cert",
                    {"Content-Disposition": 'attachment; filename="lan-proxy-root-ca.crt"'},
                )
                return
            if path == "/healthz":
                self.send_bytes(200, b"ok\n", "text/plain; charset=utf-8")
                return

            host = self.request_host()
            url_host = f"[{host}]" if ":" in host else host
            secure_url = f"https://{url_host}:{tls_port}/"
            host_is_covered = host.lower() in {value.lower() for value in certificate_hosts}
            coverage_message = (
                f'<p class="ok"><strong>Certificate name check:</strong> {html.escape(host)} is included in the server certificate.</p>'
                if host_is_covered
                else f'<p class="warn"><strong>Certificate name warning:</strong> {html.escape(host)} is not in the server certificate. Restart the Python server while this network adapter is active.</p>'
            )
            page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set up {APP_NAME}</title><style>
:root{{color-scheme:dark;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#080d19;color:#edf3ff}}main{{width:min(92vw,760px);margin:24px;padding:30px;border:1px solid #344668;border-radius:18px;background:#111a2e}}h1{{margin-top:0}}p,li{{line-height:1.55;color:#bdc9df}}.button{{display:inline-block;margin:8px 8px 8px 0;padding:13px 17px;border-radius:10px;background:#67e8f9;color:#07111f;text-decoration:none;font-weight:800}}.secondary{{background:#a5b4fc}}code{{overflow-wrap:anywhere;color:#a5f3fc}}.warn,.ok{{padding:12px;border-radius:10px}}.warn{{background:#332317;color:#ffe0ad}}.ok{{background:#123628;color:#b7f7d5}}details{{margin-top:15px;padding:12px;border:1px solid #344668;border-radius:10px}}summary{{cursor:pointer;font-weight:750}}small{{color:#93a4c2}}
</style></head><body><main><h1>One-time certificate setup</h1>
<p>This proxy must use trusted HTTPS so sites such as Instagram and YouTube receive a secure browser context.</p>
{coverage_message}
<ol><li>Download the public root certificate below.</li><li>Import it under <strong>Trusted Authorities / Certificate Authorities</strong>, not under personal or client certificates. Enable trust for identifying websites if asked.</li><li>Fully close every browser window and reopen the browser.</li><li>Open the secure proxy, then enter the token printed on the laptop.</li></ol>
<p><a class="button" href="/lan-proxy-root-ca.crt" download>Download public root certificate</a><a class="button secondary" href="{html.escape(secure_url)}">Open secure proxy</a></p>
<p><small>SHA-256 fingerprint (compare with the laptop terminal):<br><code>{html.escape(fingerprint)}</code></small></p>
<details><summary>Chrome / Chromium / Edge instructions</summary><p>Open browser settings → Privacy and security → Security → Manage certificates. Import the downloaded file into <strong>Authorities</strong> and mark it trusted for websites. On Linux, Chrome may open the operating-system certificate manager instead.</p></details>
<details><summary>Debian / Ubuntu system trust</summary><p>Copy the downloaded PEM certificate to <code>/usr/local/share/ca-certificates/lan-proxy-root-ca.crt</code>, run <code>sudo update-ca-certificates</code>, then fully restart Chromium. Firefox may require a separate import under Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities.</p></details>
<details><summary>If Chrome still says unsafe</summary><p>Do not use “Proceed anyway.” Note the exact code: <code>ERR_CERT_AUTHORITY_INVALID</code> means the root is not trusted in this browser profile; <code>ERR_CERT_COMMON_NAME_INVALID</code> means the address is not covered; <code>ERR_CERT_DATE_INVALID</code> means a device clock or validity problem.</p></details>
<p class="warn"><strong>Security:</strong> install this CA only on a device you own and trust. Remove it when you stop using this proxy. The private signing key is never downloadable from this page.</p>
</main></body></html>""".encode("utf-8")
            self.send_bytes(
                200,
                page,
                "text/html; charset=utf-8",
                {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"},
            )

    return BootstrapHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated real-page web proxy for a trusted LAN or HTTPS VPS")
    parser.add_argument("--vps", action="store_true", help="run a loopback HTTP backend for Caddy/Nginx on a VPS")
    parser.add_argument("--public-hostname", type=validate_hostname, help="public DNS name required in VPS mode")
    parser.add_argument("--public-port", type=validate_port, default=443, help="public HTTPS port in VPS mode (default: 443)")
    parser.add_argument("--host", help="listen address (default: 0.0.0.0 for LAN, 127.0.0.1 for VPS)")
    parser.add_argument("--port", type=validate_port, default=8080, help="setup page port, or backend port in VPS mode (default: 8080)")
    parser.add_argument("--tls-port", type=validate_port, default=8443, help="secure LAN proxy port (default: 8443)")
    parser.add_argument("--cross-port", type=validate_port, help="internal cross-domain port (default: main proxy port + 1)")
    parser.add_argument(
        "--access-token",
        help="token entered on the login page; alternatively set LAN_PROXY_ACCESS_TOKEN",
    )
    args = parser.parse_args()

    if args.vps and not args.public_hostname:
        parser.error("--public-hostname is required with --vps")
    if not args.vps and args.public_hostname:
        parser.error("--public-hostname can only be used with --vps")

    bind_host = args.host or ("127.0.0.1" if args.vps else "0.0.0.0")
    proxy_port = args.port if args.vps else args.tls_port
    cross_port = args.cross_port or proxy_port + 1
    ports = [proxy_port, cross_port] if args.vps else [args.port, proxy_port, cross_port]
    if cross_port > 65535 or len(set(ports)) != len(ports):
        parser.error("the configured ports must be valid and different")
    configured_token = args.access_token or os.environ.get("LAN_PROXY_ACCESS_TOKEN")
    if args.vps and not configured_token:
        parser.error("VPS mode requires --access-token or the LAN_PROXY_ACCESS_TOKEN environment variable")
    minimum_token_length = 16 if args.vps else 8
    if configured_token is not None and len(configured_token) < minimum_token_length:
        parser.error(f"--access-token must contain at least {minimum_token_length} characters in this mode")

    node = shutil.which("node.exe") or shutil.which("node")
    if not node:
        raise SystemExit("Node.js 20 or newer is required. Install Node.js, then run this command again.")
    ensure_node_dependencies(node)
    if os.name != "nt":
        os.umask(0o077)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        DATA_DIR.chmod(0o700)

    addresses: list[str] = []
    root_cert: Path | None = None
    root_key: Path | None = None
    server_cert: Path | None = None
    server_key: Path | None = None
    fingerprint = ""
    if not args.vps:
        addresses = discover_lan_addresses()
        root_cert, root_key, server_cert, server_key, fingerprint = ensure_certificates(addresses, bind_host)

    token = configured_token or secrets.token_urlsafe(24)
    control_token = secrets.token_urlsafe(24)
    diagnostic_directory = DATA_DIR / "diagnostics"
    diagnostic_directory.mkdir(parents=True, exist_ok=True)
    mode_name = "vps" if args.vps else "lan"
    diagnostic_log = diagnostic_directory / f"{mode_name}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%SZ')}-{os.getpid()}.jsonl"
    environment = os.environ.copy()
    environment.update(
        {
            "LAN_PROXY_HOST": bind_host,
            "LAN_PROXY_PORT": str(proxy_port),
            "LAN_PROXY_CROSS_PORT": str(cross_port),
            "LAN_PROXY_TOKEN": token,
            "LAN_PROXY_CONTROL_TOKEN": control_token,
            "LAN_PROXY_DATA_DIR": str(DATA_DIR),
            "LAN_PROXY_DIAGNOSTIC_LOG": str(diagnostic_log),
        }
    )
    if args.vps:
        environment.update(
            {
                "LAN_PROXY_TLS_ENABLED": "0",
                "LAN_PROXY_PUBLIC_PROTOCOL": "https:",
                "LAN_PROXY_PUBLIC_HOSTNAME": str(args.public_hostname),
                "LAN_PROXY_PUBLIC_PORT": str(args.public_port),
                "LAN_PROXY_PUBLIC_CROSS_PORT": str(args.public_port),
            }
        )
    else:
        assert server_cert is not None and server_key is not None
        environment.update(
            {
                "LAN_PROXY_TLS_CERT": str(server_cert),
                "LAN_PROXY_TLS_KEY": str(server_key),
            }
        )

    setup_server: BootstrapHTTPServer | None = None
    if not args.vps:
        assert root_cert is not None
        try:
            setup_server = BootstrapHTTPServer(
                (bind_host, args.port),
                make_bootstrap_handler(
                    root_cert,
                    args.tls_port,
                    fingerprint,
                    {"127.0.0.1", "localhost", socket.gethostname(), *addresses},
                ),
            )
        except OSError as error:
            raise SystemExit(f"Could not listen on setup port {args.port}: {error}") from error
        setup_thread = threading.Thread(target=setup_server.serve_forever, name="certificate-setup", daemon=True)
        setup_thread.start()

    print(f"\n{APP_NAME} is starting. No Chrome window will open.")
    if args.vps:
        print("ACCESS TOKEN: configured (hidden from service logs)")
    else:
        print(f"ACCESS TOKEN: {token}")
    print(f"DIAGNOSTIC LOG: {diagnostic_log.resolve()}")
    if args.vps:
        public_port_suffix = "" if args.public_port == 443 else f":{args.public_port}"
        public_url = f"https://{args.public_hostname}{public_port_suffix}/"
        print("\n================ VPS MODE ================")
        print(f"Private backend: http://{bind_host}:{proxy_port}/")
        print(f"Public URL: {public_url}")
        print("TLS must terminate at Caddy, Nginx, or another HTTPS reverse proxy.")
        print("Example Caddyfile:")
        print(f"  {args.public_hostname}{public_port_suffix} {{")
        print(f"      reverse_proxy 127.0.0.1:{proxy_port}")
        print("  }")
        if bind_host not in {"127.0.0.1", "::1", "localhost"}:
            print("WARNING: the backend is not loopback-only. Restrict it with your firewall.")
        print("==========================================")
    else:
        assert root_cert is not None and root_key is not None
        print("\n========== CERTIFICATE SETUP ==========")
        print(f"PUBLIC root certificate (install this):\n  {root_cert.resolve()}")
        print(f"SHA-256 fingerprint:\n  {fingerprint}")
        print(f"PRIVATE signing key (NEVER copy or share):\n  {root_key.resolve()}")
        print("=======================================")
        print(f"\nThis laptop setup page: http://127.0.0.1:{args.port}/")
        for index, address in enumerate(addresses):
            label = "Other-device setup (recommended)" if index == 0 else "Other local adapter"
            print(f"{label}: http://{address}:{args.port}/")
            print(f"  Secure proxy after install: https://{address}:{args.tls_port}/")
        if not addresses:
            print(f"Other device: http://THIS-LAPTOP-LAN-IP:{args.port}/")
        print(f"Windows Firewall must allow TCP {args.port}, {args.tls_port}, and {cross_port} on Private networks.")
        print("Download/install the public CA from the setup page, restart the browser, then open the secure proxy.")
    print("Press Ctrl+C here to stop.\n", flush=True)

    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    process = subprocess.Popen([node, str(ROOT / "proxy_engine.js")], cwd=ROOT, env=environment, creationflags=creation_flags)
    try:
        while process.poll() is None:
            time.sleep(0.25)
        return_code = int(process.returncode or 0)
    except KeyboardInterrupt:
        print("\nStopping proxy…", flush=True)
        return_code = 0
    finally:
        if process.poll() is None:
            shutdown_host = bind_host
            if bind_host == "0.0.0.0":
                shutdown_host = "127.0.0.1"
            elif bind_host == "::":
                shutdown_host = "::1"
            url_host = f"[{shutdown_host}]" if ":" in shutdown_host else shutdown_host
            scheme = "http" if args.vps else "https"
            shutdown_url = f"{scheme}://{url_host}:{proxy_port}/__control/shutdown"
            handlers = [ProxyHandler({})]
            if not args.vps:
                assert root_cert is not None
                try:
                    handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=str(root_cert))))
                except OSError:
                    pass
            try:
                shutdown_request = Request(
                    shutdown_url,
                    data=b"",
                    method="POST",
                    headers={"X-Lan-Proxy-Control": control_token},
                )
                build_opener(*handlers).open(shutdown_request, timeout=3).close()
            except OSError:
                if sys.platform == "win32":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if setup_server is not None:
            setup_server.shutdown()
            setup_server.server_close()
    raise SystemExit(return_code)


if __name__ == "__main__":
    main()
