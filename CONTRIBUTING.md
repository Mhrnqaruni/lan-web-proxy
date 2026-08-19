# Contributing

Thanks for helping improve LAN Web Proxy.

1. Open an issue for substantial behavior or security changes before writing
   a large patch.
2. Create a focused branch and do not commit `.proxy_data/`, browser profiles,
   logs, credentials, or generated certificates.
3. Run the checks below before opening a pull request.

```bash
python -m pip install -r requirements.txt
npm ci --ignore-scripts
npm run prepare-engine
python -m unittest discover -s tests -v
python -m py_compile proxy_server.py
npm run check
```

Describe what changed, how it was tested, and any browser/site compatibility
tradeoffs. Security reports must follow [SECURITY.md](SECURITY.md), not public
issues.
