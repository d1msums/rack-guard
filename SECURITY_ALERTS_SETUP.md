# Add the Security Alerts dashboard (v7)

This package includes the entire v6 dashboard plus Security Alerts. It works with the existing receiver's `security_alerts.jsonl`; no receiver restart, certificate change, database migration or Pi upgrade is required. Use this guide whether you have installed v6 or are adding the dashboard for the first time.

## What appears

* **High:** invalid message signature, rejected reused/lower sequence, certificate/device identity mismatch, receiver storage failure.
* **Warning:** rate limiting, unknown device, stale/future timestamp, oversized payload, invalid input.
* **Information:** unsupported HTTP method, such as GET /events.
* **Database integrity:** current count of invalid signed records in the latest 200 rows, shown separately from receiver rejection history.

These are observations, not proof of a hostile actor. The description explains possible configuration faults too. A storage failure is an operational high-priority event, not an attack determination.

The panel shows the latest 100 supported records from at most the final 256 KiB of the log. It refreshes every three seconds. Counts are for that window, not all-time totals. New high-priority records less than 90 seconds old raise a banner; already-seen records do not repeatedly notify in the same browser session. Dismiss notice hides only the banner. It never deletes or acknowledges records on the server. Reloading the page starts a new browser notification session.

The existing log does not reliably record device or source IP. This update does not invent attribution. Missing logs, unreadable logs, malformed lines and partial writes are handled explicitly. TLS handshake failures occur before Flask and are not included. Alerts are server-generated audit records, not Pi-signed evidence; full VM compromise can alter them.

## 1. Transfer the ZIP from Windows

PowerShell:

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Dashboard-v7.zip" delta@172.16.40.10:~/
```

## 2. Extract to a fresh VM directory

VM terminal:

```bash
cd ~
if [ -e "$HOME/RackGuard-Dashboard-v7" ]; then
  echo "STOP: v7 folder already exists; do not overwrite your local settings"
else
  python3 -m zipfile -e RackGuard-Dashboard-v7.zip .
fi
```

Continue only after a successful extraction into the new directory.

```bash
cd ~/RackGuard-Dashboard-v7
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 3. Preserve the current configuration and password

On the VM, from the v7 folder:

```bash
if [ -f "$HOME/RackGuard-Dashboard-v6/config.json" ]; then
  cp -n "$HOME/RackGuard-Dashboard-v6/config.json" ./config.json
else
  cp -n "$HOME/RackGuard-Stage2-Ed25519-mTLS/config.json" ./config.json
fi

if [ -f "$HOME/RackGuard-Dashboard-v6/.env" ]; then
  cp "$HOME/RackGuard-Dashboard-v6/.env" ./.env
fi
chmod 600 config.json .env
```

This copies the active operator settings into the newly extracted folder. If your installed folder differs, use that location instead. Keep `log_dir` pointing to the same receiver directory, normally `~/.local/state/coldguard`. If COLDGUARD_CONFIG in .env names the old v6 config, it remains usable while that file exists; you can update it to the v7 config path.

For first-time setup only (or if the copied .env still has an empty password hash):

```bash
python setup_dashboard.py
```

Choose a password of at least 12 characters. Default dashboard username: `operator`. Do not regenerate any Pi or VM certificates.

## 4. Check the log source and tests

```bash
ls -lh ~/.local/state/coldguard/security_alerts.jsonl
python -m unittest -v test_security test_mtls test_dashboard test_alerts
```

Expected test result: **35 tests, OK**. A missing log before the first rejection is normal and the UI says so. If using a different log_dir, check that configured directory instead. The tests use temporary data and do not write your real database/log.

Screenshot: `S2-alerts-01-tests.png` (do not include secrets).

## 5. Start the updated dashboard

If v6 dashboard.py is running, press Ctrl+C in its terminal. Leave the separate receiver.py and Pi sender running.

VM, v7 environment:

```bash
cd ~/RackGuard-Dashboard-v7
source .venv/bin/activate
python -u dashboard.py
```

Expected: `http://127.0.0.1:18080`. Only one dashboard can use that port.

## 6. Open through SSH

Keep an existing working tunnel, or open this in Windows PowerShell:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18080:127.0.0.1:18080 delta@172.16.40.10
```

Open **http://127.0.0.1:18080/**, log in as operator, and hard-refresh once (Ctrl+F5). Click **Security Alerts**. Do not open VM port 18080 in the firewall and do not change the mTLS requirement on 18443.

Screenshot: `S2-alerts-02-panel.png`.

## 7. Produce one safe, real rejection for the demo

This test submits exactly one simulated temperature message modified after signing. The receiver should reject it; no fake temperature is accepted. One Pi sequence is allocated, which is safe because sequence gaps are allowed.

Windows PowerShell:

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Dashboard-v7\demo_alert.py" techtarik@10.40.40.20:/home/techtarik/RackGuard-Stage2-Ed25519-mTLS/demo_alert.py
```

Pi:

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
source .venv/bin/activate
python demo_alert.py
```

Expected:

```text
HTTP 403 ... BAD_AUTHENTICATION ...
PASS: modified message rejected. Open Security Alerts; expect Invalid message signature within the next poll.
```

The browser should show **HIGH · Invalid message signature** and a red suspicious-activity banner within roughly three seconds. If the receiver returns 429, stop the normal sender briefly, wait 15 seconds and run the one-message test again; restart the sender afterward. Do not repeatedly run the test at high speed.

Screenshots:

* `S2-alerts-03-pi-rejection.png`
* `S2-alerts-04-live-banner.png`

Click Dismiss notice and wait one poll: the record stays in the panel, and the same record should not raise another banner until the page is reloaded.

## 8. Judge explanation

“The receiver rejects an invalid request and writes an audit record. The authenticated dashboard reads that record and shows the reason and severity. The operator can see suspicious activity quickly, but the dashboard cannot change device permissions or weaken message checks. Configuration problems can also cause rejections, so we do not label every alert as a confirmed attack.”

## Troubleshooting and rollback

* **No log yet:** confirm a rejection actually occurred on the active receiver and that log_dir matches.
* **Feed unavailable:** check read permissions on the configured log directory; do not use chmod 777. Other live panels can continue independently.
* **Record present but no banner:** only high-priority records under 90 seconds old notify, once per page session. Check VM time if necessary.
* **TLS handshake failed but no alert:** expected limitation; this feed covers application rejections only.
* **Old records disappeared:** the reader uses a bounded recent tail and detects rotated/truncated files on the next poll. Keep external evidence separately.
* **Rollback:** stop v7 dashboard.py and restart your v6 dashboard. No database restore is needed.

The `.env` included in the ZIP has placeholders only. Never commit a populated `.env`, private keys or live database to source control. `.gitignore` does not apply to SVN; review the SVN pending file list and use svn:ignore as appropriate.
