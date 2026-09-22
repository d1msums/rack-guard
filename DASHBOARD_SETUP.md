# RackGuard dashboard integration (v7 package, v5.0 product UI)

## What changed

The supplied dashboard2.html is now templates/dashboard.html. Its dark layout, five tabs and background are retained. The supplied image attachment is a PNG, so it is saved honestly as static/rackguard-background.png rather than renamed to JPG. CSS and chart code are local; the UI needs no CDN or internet connection.

The original mock LLM report, random latency, fabricated uptime and cold-storage 2–8°C lockdown display have been removed. Charts use recent real database records. No physical lockdown action is performed. Simulation badges follow the signed event flag.

## Trust boundaries and routing

* Pi -> VM: **https://172.16.40.10:18443/events**, unchanged required mTLS, pinned client certificate, Ed25519 signatures, freshness, counters, rate limits and database transactions.
* Browser -> local laptop port **18080** -> encrypted, authenticated **SSH tunnel** -> VM **127.0.0.1:18080** -> a separate Flask dashboard.
* The dashboard requires its own operator username/password. It never accepts a Pi certificate as operator authorization. The browser never receives a Pi private key.
* Dashboard SQLite connections use `mode=ro` and `PRAGMA query_only`. The UI has no POST ingestion route and cannot change authorization, counters or rows.

Do **not** change mTLS to optional client certificates, open port 18080 on the VM firewall, or bind dashboard.py to 0.0.0.0. The browser address is HTTP on laptop loopback, but the laptop-to-VM leg is encrypted by SSH. This is an intentional local tunnel design, not public HTTP. For future public HTTPS, use a separate operator hostname/service with operator authentication and a browser-trusted server certificate; preserve the independent mTLS ingestion listener.

## 1. Transfer and extract on the VM

Keep the existing receiver and sender running. This dashboard requires no change on the Pi and no ingestion restart.

Windows PowerShell (the archive is produced in this workspace):

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Dashboard-v7.zip" delta@172.16.40.10:~/
```

VM:

```bash
cd ~
python3 -m zipfile -e RackGuard-Dashboard-v7.zip .
cd ~/RackGuard-Dashboard-v7
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp -n ~/RackGuard-Stage2-Ed25519-mTLS/config.json ./config.json
chmod 600 config.json .env
```

Extract only into a fresh folder. If this folder already contains local changes, use a new directory instead. Use the active VM configuration if your installed application folder differs. Do not copy the old HMAC-only configuration: the dashboard needs the enrolled Ed25519 public-key paths. Existing public keys and database remain in their configured locations. Do not regenerate certificates or reset counters.

## 2. Set the operator password

VM, new environment active:

```bash
python setup_dashboard.py
```

Enter and repeat a password of at least 12 characters. Input is hidden. Only a password hash is stored in .env. Default username: **operator**. Password setup does not change VM/SSH credentials.

The included .env contains placeholders only. .env.example is the safe source-controlled template. Shell environment variables override .env. If a stale DASHBOARD_PASSWORD_HASH is exported in your shell, unset it before starting the service.

## 3. Start the dashboard

VM:

```bash
python -u dashboard.py
```

Expected listener: `http://127.0.0.1:18080`. Keep this terminal open. The existing `receiver.py` continues separately on 18443.

## 4. Open the SSH tunnel and browser

Windows PowerShell, in another window:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18080:127.0.0.1:18080 delta@172.16.40.10
```

Enter the VM SSH password if prompted. The terminal stays open without printing a shell prompt; that means it is maintaining the tunnel.

Open **http://127.0.0.1:18080/** in your Windows browser. Enter `operator` and the dashboard password when the browser prompts. Close the private browser session to clear cached HTTP Basic credentials when finished. The tunnel ends with Ctrl+C.

## 5. Check live data

The dashboard polls `/api/events?limit=200` every three seconds. It reads the latest bounded window directly from SQLite; you do not need to regenerate events.jsonl.

* Valid signed rows appear in the temperature chart and event stream.
* RFID tokens are masked in the interface; access results come from the receiver's stored decision.
* Invalid signatures or changed signed fields are withheld and counted as integrity alerts.
* Records without cryptographic proof, including old HMAC-era rows, are withheld and counted as unverifiable. No claims of validation are made for them.
* Temperature older than 15 seconds is marked stale independently of dashboard connectivity.
* Network Health shows measured browser API latency and successful polls for this browser session. It is not Pi ping, total VM uptime, or Uptime Kuma integration.

The temperature chart shows the latest verified readings within the recent 200 database rows, not an entire history. Receive times and access_granted are server-derived metadata, not covered by the Pi signature. The dashboard does not claim to detect deleted rows, full database rollback or a fully compromised server.

## 6. LLM analysis

The original HTML only simulated a critical threat and confidence score. This integration displays actual reports with model, generation time, event count and a stale-report indicator; it never invents a score.

### Existing AI teammate's worker

It can atomically publish a UTF-8 JSON file at `~/.local/state/coldguard/analysis.json` (or RACKGUARD_ANALYSIS_FILE in .env):

```json
{
  "model": "actual-model-name",
  "generated_at": "2026-09-20T00:00:00+00:00",
  "events_analyzed": 20,
  "summary": "Actual analysis text from your model."
}
```

This is a schema example, not a report to deploy. Keep it outside static/. The authenticated `/api/analysis` reads at most 64 KiB and returns selected fields only. Reports older than five minutes are labelled stale. Treat model text as advisory and untrusted; the browser renders it using textContent, not executable HTML. The UI refreshes every 15 seconds, and REFRESH REPORT rereads an existing report without invoking a model or incurring a cost.

### Optional included local Ollama worker

If a suitable model is already installed in Ollama on the VM, set `OLLAMA_MODEL` to its exact name in .env and run:

```bash
python analysis_worker.py
```

This one-shot worker reads up to 100 signature-verified events, removes card aliases, and submits only event type, timestamp, temperature, access decision and simulation flag to `127.0.0.1:11434/api/generate`. It writes a report atomically. It has no authorization or actuator control. No external AI service is contacted. A running Ollama service and installed model are prerequisites; no model is bundled or automatically downloaded. For a small VM, prefer the teammate's existing analysis worker rather than loading a large model.

Ollama request format follows its official [Generate API](https://docs.ollama.com/api/generate). The actual model inference must be tested on your deployment; automated tests use a mocked local model response.

## Security tests and evidence

```bash
python -m unittest -v test_security test_mtls test_dashboard test_alerts
```

The original trust suite must still pass. New coverage checks operator authentication, protected assets, bounded read-only APIs, live inserts, tamper filtering, safe missing-database handling, separate ingestion routing and unavailable/stale analysis reports.

Capture:

* `S2-dashboard-01-login.png`: browser authentication prompt (no password visible).
* `S2-dashboard-02-live-data.png`: real telemetry or clearly labelled simulation.
* `S2-dashboard-03-temperature-chart.png`: chart and sample count.
* `S2-dashboard-04-health.png`: actual API polling and integrity status.
* `S2-dashboard-05-analysis.png`: actual model report, or explicitly unavailable.

## Source control and rollback

.gitignore excludes live config, certs, private keys, databases, JSONL logs, analysis reports and virtual environments. It does not remove secrets already tracked. SVN does not use .gitignore: review the SVN pending file list and set svn:ignore properties before submission. Include only code, templates, static assets, tests, documentation and .env.example. Do not submit the populated .env.

To roll back **this dashboard addition**, stop dashboard.py and close the tunnel. No database restoration is needed because the dashboard only reads. This differs from rolling back the earlier ingestion-schema migration.

## Operational limits

The dashboard uses Flask's development server for the hackathon and HTTP Basic credentials over a local SSH tunnel. Login attempt throttling is process-local. A fully compromised VM can bypass local code, modify server-derived fields or read local files. Production deployment should use a dedicated read-only OS account, production WSGI server, managed operator sessions and audited report generation.
