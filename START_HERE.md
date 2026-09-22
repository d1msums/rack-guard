# RackGuard Complete v8 — consolidated release

Includes v7 dashboard/security alerts, Gemini worker, server-confirmed RFID access display, and the latest hardware adapter with green BCM GPIO22, red BCM GPIO23 and LCD address 0x27. The LED wiring is active-high through resistors toward GND. Authorization still comes from the server; HTTP 201 alone does not grant access. This package does not operate a physical door lock.

This is a consolidation of the code developed in this conversation, not a download of your live Pi/VM files. Preserve any additional teammate changes before deployment. Do not apply during an unresolved network disruption.

## Keep your existing configuration

The included .env is a blank template, NOT your configured dashboard login/Gemini key. The archive contains no live config.json, private keys, certificate material, databases or enrolled card tokens.

Never extract over a working folder or copy the template .env over your configured .env. Do not regenerate certificates, reset counters or replace your authorized_cards mapping.

## Deploy as a new folder

Copy the ZIP from Windows to each machine:

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Complete-v8.zip" delta@172.16.40.10:~/
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Complete-v8.zip" techtarik@10.40.40.20:~/
```

On BOTH machines, extract once into a new directory:

```bash
cd ~
test ! -e RackGuard-Complete-v8 && python3 -m zipfile -e RackGuard-Complete-v8.zip .
```

If the folder already exists, stop and inspect it rather than overwriting it.

### VM preparation

```bash
cd ~/RackGuard-Complete-v8
cp ~/RackGuard-Stage2-Ed25519-mTLS/config.json ./config.json
cp ~/RackGuard-Dashboard-v7/.env ./.env
chmod 600 config.json .env
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v test_security test_mtls test_dashboard test_alerts test_gemini test_access
```

Use the actual active receiver config if its location differs. Existing configured absolute or home-relative key and log paths remain valid. If your config uses relative key/log paths, resolve them to their existing absolute locations before switching; do not create a new empty state database.

If COLDGUARD_CONFIG in .env names an older config, point it to /home/delta/RackGuard-Complete-v8/config.json before running the new services. Likewise use the same RACKGUARD_ANALYSIS_FILE as before. Do not print .env in screenshots.

Stop the OLD receiver, dashboard and Gemini worker in their respective terminals, then start these in three separate VM terminals:

```bash
cd ~/RackGuard-Complete-v8
source .venv/bin/activate
python -u receiver.py
```

```bash
cd ~/RackGuard-Complete-v8
source .venv/bin/activate
python -u dashboard.py
```

```bash
cd ~/RackGuard-Complete-v8
source .venv/bin/activate
python gemini_worker.py --watch
```

Only run Gemini if configured; it uses API quota. If the key is missing, run setup_gemini.py privately first. Do not run multiple workers writing the same analysis report.

### Pi preparation

Stop the old sender before starting the new one. To avoid rebuilding your already-working hardware libraries, this release can use the existing Pi virtual environment:

```bash
cd ~/RackGuard-Complete-v8
cp ~/RackGuard-Stage2-Ed25519-mTLS/config.json ./config.json
chmod 600 config.json
source ~/RackGuard-Stage2-Ed25519-mTLS/.venv/bin/activate
python -m pip install -r requirements.txt -r requirements-hardware.txt
python -u sender.py
```

The hardware pin assignments are embedded in hardware.py. No red/green pin exports are required. The existing GPIOZERO_PIN_FACTORY setting, if explicitly set, takes precedence; lgpio is the default when unset. Existing LCD environment overrides still apply.

### Windows browser tunnel

Keep your existing working tunnel, or run:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:18080:127.0.0.1:18080 delta@172.16.40.10
```

Open http://127.0.0.1:18080/ in Edge/Chrome. Use the existing dashboard login. Ingestion remains required mTLS on 18443. No firewall changes are needed.

## Verify after switching

1. Sender receives 201 and dashboard readings update.
2. Authorized card shows ACCESS GRANTED/green. An unenrolled card shows ACCESS DENIED/red.
3. Server unavailable or invalid response shows NO DECISION; neither LED grants access.
4. Hold each card until detected and remove it between scans. RFID sampling is still roughly every five seconds plus network time; fast taps can be missed.
5. Demo rejection appears in Security Alerts; Gemini report appears separately as advisory.

Back up before changing the card allowlist. The older ACCESS_SETUP.md explains enrollment but references the previous deployment folder; for this deployment use ~/RackGuard-Complete-v8/config.json and restart this receiver.

## Guides and limitations

README.md contains the locked project narrative. DASHBOARD_LOCALHOST_WALKTHROUGH.md, DASHBOARD_SETUP.md, SECURITY_ALERTS_SETUP.md, ACCESS_SETUP.md and GEMINI_SETUP.md retain their original v7/add-on paths for existing installations. For the unified v8 deployment, follow this START_HERE.md and substitute the v8 directory when using their diagnostic commands.

The hardware update preserves the server decision model. Signed telemetry is not proof of physical sensor accuracy; RFID pseudonymization is not cloning prevention. Gemini is not enforcement. Services are manually started; do not claim automatic recovery. No guarantee of physical LEDs is made without testing the final installation.

## Rollback

Stop the v8 processes, then start the previous receiver/sender/dashboard from their original directories. Persistent state remains at the existing configured paths; do not restore older counter/database copies. This release adds response fields but does not migrate the database schema. Keep only one sender and one receiver active.
