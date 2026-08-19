# VPS deployment guide

This guide exposes the proxy at a normal HTTPS domain without a tunneling
service. Caddy or Nginx owns the public ports and TLS certificate; the browser
proxy remains private on loopback.

## 1. Prerequisites

- A Linux VPS with a public IP
- A DNS name such as `proxy.example.com`
- Inbound TCP ports `80` and `443` allowed by the provider firewall and OS
- Python 3.10+, Node.js 20+, npm, Git, and Caddy or Nginx

Point the hostname's `A` record to the IPv4 address. Add an `AAAA` record only
when IPv6 is configured and reachable on the VPS.

## 2. Create an unprivileged service account

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin lanproxy
sudo mkdir -p /opt/lan-web-proxy
sudo chown lanproxy:lanproxy /opt/lan-web-proxy
```

Clone and install as that account:

```bash
sudo -u lanproxy git clone https://github.com/Mhrnqaruni/lan-web-proxy.git /opt/lan-web-proxy
sudo -u lanproxy python3 -m venv /opt/lan-web-proxy/.venv
sudo -u lanproxy /opt/lan-web-proxy/.venv/bin/pip install -r /opt/lan-web-proxy/requirements.txt
sudo -u lanproxy npm ci --prefix /opt/lan-web-proxy --omit=dev --ignore-scripts
sudo -u lanproxy npm run --prefix /opt/lan-web-proxy prepare-engine
sudo -u lanproxy mkdir -p /opt/lan-web-proxy/.proxy_data
```

## 3. Create the secret

Generate a random token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Create `/etc/lan-web-proxy.env` containing the generated value:

```text
LAN_PROXY_ACCESS_TOKEN=replace-with-the-generated-value
```

Protect it:

```bash
sudo chown root:lanproxy /etc/lan-web-proxy.env
sudo chmod 640 /etc/lan-web-proxy.env
```

## 4. Install the systemd service

Copy the provided template:

```bash
sudo cp /opt/lan-web-proxy/deploy/lan-web-proxy.service /etc/systemd/system/
sudo sed -i 's/proxy\.example\.com/YOUR.REAL.HOSTNAME/g' /etc/systemd/system/lan-web-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now lan-web-proxy
sudo systemctl status lan-web-proxy
```

Confirm that only loopback owns the backend ports:

```bash
ss -ltnp | grep -E ':(8080|8081)\b'
curl http://127.0.0.1:8080/healthz
```

The health response should be `ok`, and the listening addresses should be
`127.0.0.1`, not `0.0.0.0`.

## 5. Configure Caddy

Install Caddy using its [official installation guide](https://caddyserver.com/docs/install).
Add this site to `/etc/caddy/Caddyfile`:

```caddyfile
proxy.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo journalctl -u caddy -n 100 --no-pager
```

Caddy preserves the original HTTP `Host` for an HTTP upstream and handles
WebSocket upgrades. With correct public DNS and reachable ports 80/443, it
automatically obtains and renews the certificate. See Caddy's
[reverse-proxy quick start](https://caddyserver.com/docs/quick-starts/reverse-proxy).

## Nginx alternative

Use a certificate manager such as Certbot, then configure the HTTPS server:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }
}
```

Place the `map` in Nginx's `http` context, outside the `server` block.

## Updating

```bash
sudo systemctl stop lan-web-proxy
sudo -u lanproxy git -C /opt/lan-web-proxy pull --ff-only
sudo -u lanproxy npm ci --prefix /opt/lan-web-proxy --omit=dev --ignore-scripts
sudo -u lanproxy npm run --prefix /opt/lan-web-proxy prepare-engine
sudo -u lanproxy /opt/lan-web-proxy/.venv/bin/pip install -r /opt/lan-web-proxy/requirements.txt
sudo systemctl start lan-web-proxy
```

Review release notes and back up `.proxy_data/` privately before major updates.

## Troubleshooting

### Caddy returns 502

Check the backend and service logs:

```bash
curl -v http://127.0.0.1:8080/healthz
sudo journalctl -u lan-web-proxy -n 200 --no-pager
```

### Certificate is unavailable

Verify DNS from outside the VPS, confirm ports 80/443 are open, and inspect the
Caddy journal. Do not expose port 8080 as a workaround.

### Generated links use the wrong hostname

The `--public-hostname` value in the systemd unit and the hostname in the
Caddyfile must be identical. Reload both services after correcting them.

### Login stops accepting attempts

Repeated failures trigger a temporary rate limit. Wait five minutes, confirm
the configured secret, and retry. Do not weaken or remove the rate limit.
