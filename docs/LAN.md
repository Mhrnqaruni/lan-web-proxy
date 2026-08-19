# LAN setup guide

This mode is intended for devices on the same trusted local network. The host
creates a private root certificate so the proxied pages have a secure browser
context.

## Host installation

Install Python 3.10+, Node.js 20+, and Git. Then:

```powershell
git clone https://github.com/Mhrnqaruni/lan-web-proxy.git
cd lan-web-proxy
python -m pip install -r requirements.txt
npm ci --omit=dev --ignore-scripts
python .\proxy_server.py
```

Linux/macOS use `python3 proxy_server.py` instead. Keep the terminal open.

## Client certificate installation

Open the HTTP setup URL printed by the host, download the public root CA, and
compare its SHA-256 fingerprint with the host terminal before trusting it.

### Chrome, Chromium, or Edge

Open browser settings, search for **Manage certificates**, import the file under
**Authorities** or **Trusted Root Certification Authorities**, and enable trust
for identifying websites. Fully close all browser windows and reopen them.

### Firefox

Open Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import. Select the downloaded certificate and trust it to
identify websites. Restart Firefox.

### Debian or Ubuntu system trust

```bash
sudo cp lan-proxy-root-ca.crt /usr/local/share/ca-certificates/lan-proxy-root-ca.crt
sudo update-ca-certificates
```

Restart the browser. Firefox may still require the separate import above.

## Certificate errors

- `ERR_CERT_AUTHORITY_INVALID`: the CA is not trusted by that browser profile.
- `ERR_CERT_COMMON_NAME_INVALID`: the IP address is not in the generated server
  certificate. Restart the Python server while that network adapter is active.
- `ERR_CERT_DATE_INVALID`: check the clocks on both devices.

Do not work around these errors with **Proceed anyway**. Fix certificate trust
and restart the browser.

## Firewall

Allow only local-subnet clients to reach the three LAN ports. On Windows, run
PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "LAN Web Proxy" -Direction Inbound -Protocol TCP -LocalPort 8080,8443,8444 -Action Allow -Profile Private -RemoteAddress LocalSubnet
```

Do not create a router port-forward for LAN mode.

## Removing the local CA

When the proxy is no longer needed, remove **LAN Web Proxy Local Root CA** from
the client device's trusted authorities. Stop the server before removing or
archiving `.proxy_data/` on the host.
