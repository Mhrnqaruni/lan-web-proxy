# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Please do not publish an exploit or sensitive report in a public issue. Use
GitHub's private vulnerability reporting for this repository. Include the
affected revision, operating system, reproduction steps, and expected impact.

## Deployment boundaries

This application processes authentication cookies and browsing sessions. Its
`.proxy_data/` directory is sensitive and must never be published or shared.

- Keep the login token long, random, and private.
- In VPS mode, leave the backend bound to `127.0.0.1` and expose only the HTTPS
  reverse proxy.
- Do not enable access to private destination addresses on an Internet-facing
  deployment.
- Run the service as an unprivileged operating-system account.
- Keep runtime files private; the provided systemd unit uses a restrictive
  process umask and the launcher restricts private files on POSIX systems.
- Stop the service and remove the local root CA when LAN access is no longer
  needed.

This is an authenticated browsing tool, not an anonymity service. Destination
sites see the network address of the machine running the proxy.
