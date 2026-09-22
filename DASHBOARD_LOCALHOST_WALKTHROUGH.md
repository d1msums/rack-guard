# RackGuard dashboard: localhost walkthrough

This guide uses your existing installation. The dashboard runs on the Linux VM; your Windows browser opens it at **http://127.0.0.1:18080/** through an SSH tunnel.

You do not need to copy the database to Windows or install Flask on Windows. Keep the existing certificates, keys and sequence counters unchanged.

## 1. Understand the terminals

Keep these processes in separate terminals:

1. **VM receiver** — accepts Pi telemetry on HTTPS port 18443.
2. **Pi sender** — reads hardware and sends telemetry.
3. **VM dashboard** — serves the website on VM loopback port 18080.
4. **Windows SSH tunnel** — connects your laptop's localhost port to the VM dashboard.
5. **VM Gemini worker, optional** — periodically creates AI reports.

The website needs terminals 3 and 4. Fresh readings also need 1 and 2. AI updates need 5.

If a process is already running correctly, leave it running. Do not start duplicate copies. Pressing Ctrl+C stops the foreground process; closing its terminal may also stop it.

## 2. Check your connection

Connect your laptop to the team's assigned network. Open Windows PowerShell and run:

```powershell
ssh delta@172.16.40.10
```

Enter the VM password. Expected prompt resembles:

```text
[delta@delta-rocky9 ~]$
```

Windows commands go at a `PS C:\Users\sofea>` prompt. VM commands go at a `delta@delta-rocky9` prompt. Pi commands go at a `techtarik@techtarik` prompt.

## 3. Start the VM dashboard

In the VM terminal opened above:

```bash
cd ~/RackGuard-Dashboard-v7
source .venv/bin/activate
python -u dashboard.py
```

Expected:

```text
Running on http://127.0.0.1:18080
```

**Leave this terminal open.** Do not stop the dashboard to run Gemini in the same terminal.

If the folder is missing, this machine does not have the v7 deployment used by this guide. Install the v7 package using its SECURITY_ALERTS_SETUP.md first.

If the dashboard reports a missing operator password, run `python setup_dashboard.py` from this folder, choose a password of at least 12 characters, then start the dashboard again. Do not reset the password if your existing login works.

## 4. Start the SSH tunnel on Windows

Open a **new Windows PowerShell tab**, not a command prompt inside the VM:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:18080:127.0.0.1:18080 delta@172.16.40.10
```

Enter your VM password.

A blank terminal after authentication is normal. This connection carries browser traffic; it does not provide an interactive VM prompt. Leave it open.

The keepalive options detect a broken SSH connection; they do not automatically reconnect it. If it exits, rerun the command after restoring connectivity.

Do not open port 18080 on the VM firewall. Do not change the dashboard bind address to 0.0.0.0. The tunnel supplies encrypted transport between laptop and VM while keeping the dashboard off the LAN.

## 5. Open the website

Open Microsoft Edge or Chrome on your Windows laptop:

**http://127.0.0.1:18080/**

Use HTTP at this local address, not HTTPS. HTTPS/mTLS remains in use for Pi ingestion on port 18443; the browser connection travels through SSH.

When prompted:

- Username: **operator**, unless you configured a different username.
- Password: your **dashboard password**, not the VM password or Gemini API key.

The dashboard should load its background and five tabs: Live Overview, Network Health, Analytics, Security Alerts and AI Analyzer.

Screenshot: `dashboard-01-localhost.png` showing the address and dashboard, without credentials.

## 6. Ensure fresh readings are arriving

The dashboard can load successfully while displaying old data. Confirm both telemetry processes are running.

### VM receiver: separate terminal

From another Windows PowerShell tab:

```powershell
ssh delta@172.16.40.10
```

Then:

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
source .venv/bin/activate
python -u receiver.py
```

Leave it running. The receiver uses **18443**, not dashboard port 18080.

### Pi sender: separate terminal

From another Windows PowerShell tab:

```powershell
ssh techtarik@10.40.40.20
```

Then:

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
source .venv/bin/activate
export LCD_I2C_ADDRESS=0x27
python -u sender.py
```

The LCD setting applies to your updated hardware adapter and confirmed LCD address. It is not a server or network setting.

Expected sender output includes `Status: 201`. Check that dashboard timestamps advance and that real versus simulated readings are labelled correctly.

Screenshot: `dashboard-02-live-readings.png`.

## 7. Show Gemini reports, optional

The Gemini add-on and API key have already been configured in your working installation. In a separate VM terminal:

```bash
cd ~/RackGuard-Dashboard-v7
source .venv/bin/activate
python gemini_worker.py
```

Expected:

```text
PASS: Gemini report saved. Open AI Analyzer; refresh within 15 seconds.
```

Open AI Analyzer. Wait up to 15 seconds or use its report refresh button.

For repeated updates:

```bash
python gemini_worker.py --watch
```

Keep that terminal open. This uses Google API quota, with a 60-second wait between completed runs. Run only one analysis worker. The dashboard refresh button reads the saved report; it does not call Gemini.

Screenshot: `dashboard-03-ai-report.png`, including model and report time. Never photograph or share the API key or populated .env.

## 8. Verify Security Alerts

Open Security Alerts. Historical records may remain after their underlying problem is fixed. An empty or missing log is not proof that no attacks occurred.

To demonstrate one rejected modified message, use your existing demo_alert.py on the Pi in a separate terminal:

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
source .venv/bin/activate
python demo_alert.py
```

Expected: HTTP 403 with BAD_AUTHENTICATION. Check the dashboard for the new invalid-signature record and banner within roughly three seconds. If rate limited, pause normal sending briefly, wait 15 seconds, retry once and resume normal sending.

Screenshot: `dashboard-04-security-alert.png`.

TLS handshake failures are not included in this application alert feed. Gemini does not enforce the rejection.

## 9. Troubleshooting

### Tunnel repeatedly prints “channel ... Connection refused”

SSH is connected, but its connection to VM localhost:18080 was refused. Start/check the dashboard using step 3. Leave the existing tunnel running if it remains connected.

In another VM terminal, check the listener:

```bash
ss -ltnp 'sport = :18080'
```

Expect a LISTEN entry for 127.0.0.1:18080. If only the header appears, no listener is shown. Inspect dashboard startup errors.

### Dashboard says “Address already in use”

Another process occupies VM port 18080. Check the listener above. If it is your working dashboard, use it instead of launching another copy. Do not kill unidentified processes.

### Windows tunnel says “Address already in use” or cannot bind

An existing tunnel or another local application may own laptop port 18080. Try the browser through the existing tunnel first. If necessary, use a different laptop port while keeping VM port 18080:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:18081:127.0.0.1:18080 delta@172.16.40.10
```

Then open **http://127.0.0.1:18081/**. No application configuration or firewall change is needed for this alternate local port.

### ERR_INVALID_AUTH_CREDENTIALS or login repeatedly fails

Try an Edge/Chrome private window and the dashboard credentials. After many failed attempts, wait at least one minute for the login rate limit. If the password is forgotten, stop only the dashboard, run setup_dashboard.py in its folder, then restart it.

### Website loads but shows “Disconnected”

The page loading and its data feed are separate checks. Read the precise dashboard message and inspect its VM terminal. A database/configuration/read-permission failure can prevent the feed even when the website itself loads. Do not use chmod 777 or reset databases to fix this.

### Website shows “STALE”

The displayed reading is old. Check sender output, receiver availability and clocks. Compare `date -u` on Pi and VM if freshness rejections occur.

### Pi reports “Connection refused” for port 18443

Check/start the receiver, not the dashboard. On the VM:

```bash
ss -ltnp 'sport = :18443'
```

Keep keys and counters unchanged. Failed sends can leave sequence gaps; do not reset the counter.

### Gemini is unavailable but readings work

Check the separate Gemini worker output, API quota and VM internet access. Previous reports become stale after five minutes. This does not require disabling telemetry security.

## 10. Keeping the demonstration running

- Keep the Windows laptop awake and on the team network.
- Keep the dashboard, tunnel and telemetry terminals open.
- Start Gemini in a separate terminal.
- If the tunnel exits, reconnect it. If dashboard.py exits, inspect its error and restart it.
- These are manually started prototype processes, not a managed production deployment with automatic recovery.
- Leave inbound dashboard port 18080 closed; preserve required mTLS on ingestion port 18443.

## 11. Stopping when finished

Press Ctrl+C in the Gemini worker to stop API usage, in the dashboard terminal to stop the website, and in the tunnel terminal to close forwarding. Stop the sender and receiver separately only when telemetry is no longer needed.

Stopping these processes does not require deleting data, keys, certificates or configuration.

**Success:** the browser opens localhost, live readings update, Security Alerts loads, and AI Analyzer displays the latest available report.
