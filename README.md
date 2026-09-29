# PulseCheck

PulseCheck is a small Linux-friendly web application that stores domains in SQLite, discovers open ports for each domain, and monitors the health of those ports on a 10-minute schedule.

## Features

- Import a list of domain names from a text block
- Detect which common ports are listening for each domain
- Maintain the domain list with add, edit, and delete actions
- Schedule automatic health checks every 10 minutes
- View a green/red status page showing online/offline port state and last successful response time
- Configure outgoing SMTP email settings and destination alert recipient

## Run

### Local environment:
1. Create a virtual environment and install dependencies:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
2. Start the app:
   python app.py
3. Open the browser at http://127.0.0.1:8182

### Docker Compose:
Build and run the containerized application directly:
```bash
docker compose up -d --build
```
The application will be accessible at http://127.0.0.1:8182 (or the configured hostname).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PULSECHECK_IP` | `0.0.0.0` | IP address for the web server to listen/bind on (`DEFAULT_IP`) |
| `PULSECHECK_HOSTNAME` | `127.0.0.1` | Hostname / domain used in HTTP/HTTPS URLs without port (e.g. `pulsecheck.example.com` or `127.0.0.1`) |
| `PULSECHECK_SSL` | `FALSE` | Set to `TRUE` (or `1`) to use `https://` instead of `http://` in generated URLs and email links |
| `PULSECHECK_PORT` | `8182` | Web server listening port |
| `PULSECHECK_HEADLESS` | `0` (or `1` in Docker) | Set to `1` to run without interactive console menu |
| `PULSECHECK_DB_PATH` | `./pulsecheck.db` | Path to the SQLite database file |
| `PULSECHECK_TIMEZONE` / `TZ` | System local time | Timezone for status page and alert timestamps (e.g. `Africa/Johannesburg`, `Europe/London`, `America/New_York`) |
| `PULSECHECK_SCAN_WORKERS` | `5` | Number of domains scanned in parallel during periodic scans |
| `PULSECHECK_SCAN_RETRIES` | `3` | Number of retries when a domain check fails during periodic scans |
| `PULSECHECK_SCAN_RETRY_INTERVAL` | `10` | Seconds to wait between scan retries |



## Menu choices

The app also includes a console menu when started directly, allowing you to:

1. Import domain list
2. Maintain domains
3. View status
4. Email & SMTP settings
5. Start web app
6. Start web with Explicit debugging
7. Exit
