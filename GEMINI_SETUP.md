# Gemini for your running RackGuard v7 dashboard

This add-on runs on the VM only. Keep the current dashboard, SSH tunnel, receiver and sender running. No certificates, firewall rules, database schema or security decisions change. Do not run the old Ollama worker at the same time: both write the same report.

## 1. Copy these files from Windows PowerShell

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Gemini-Addon\gemini_worker.py" "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Gemini-Addon\setup_gemini.py" "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Gemini-Addon\test_gemini.py" delta@172.16.40.10:~/RackGuard-Dashboard-v7/
```

Enter the VM password. These are new files; your existing configuration is preserved.

## 2. Open another VM terminal

From a new Windows PowerShell tab:

```powershell
ssh delta@172.16.40.10
```

Then on the VM:

```bash
cd ~/RackGuard-Dashboard-v7
source .venv/bin/activate
python -m unittest -v test_gemini
python setup_gemini.py
```

Expected: 6 tests, OK. Paste your Gemini API key at the hidden prompt. Do not send it in chat or take a screenshot. Get a key from https://aistudio.google.com/apikey if needed. Press Enter at the model prompt to use gemini-flash-latest, or enter a model available to your project. Model availability and quotas depend on your Google account.

The setup preserves your dashboard password and adds Gemini settings to the VM .env with owner-only permissions. It never prints the key. Do not commit .env to SVN; .gitignore does not protect SVN submissions.

## 3. Generate the first real report

```bash
python gemini_worker.py
```

This makes one HTTPS request to Google using your API quota. The VM needs outbound internet access. It sends up to 100 verified readings reduced to temperature, relative age, simulated flag and RFID access outcomes, plus bounded rejection counts from the last five minutes. It does not send card tokens, device IDs, raw rejected payloads, certificates or secrets. Server access outcomes/audit logs are not Pi-signed evidence.

Expected:

```text
PASS: Gemini report saved. Open AI Analyzer; refresh within 15 seconds.
```

Open the existing browser dashboard, click AI Analyzer, and wait up to 15 seconds or use its refresh button. That button reads the saved report; it does not call Gemini. No dashboard restart is required.

Screenshot the report with its model/time and the successful terminal message, excluding secrets.

## 4. Optional continuous analysis

```bash
python gemini_worker.py --watch
```

Keep this VM terminal open. It generates a report, waits 60 seconds, then repeats (at most roughly 60 calls per hour). Calls use Google quota and may incur charges according to your plan. Run only one worker. Ctrl+C stops AI analysis without stopping telemetry. Leave it stopped when not needed.

## Troubleshooting

* HTTP 400/401/403: check key, project permissions and model. Rerun setup_gemini.py; restart the worker afterward.
* HTTP 404: rerun setup with an available model name from Google AI Studio.
* HTTP 429: quota/rate limit; stop watch mode and check quota before retrying.
* Connection unavailable: check VM internet and outbound HTTPS. Do not disable TLS certificate verification or open inbound dashboard ports.
* No events: wait for accepted Pi telemetry. The worker skips calls if there are neither verified events nor recent rejection records.
* Incomplete report: no new report is published; try another available model or retry once. Existing report stays visible and becomes STALE REPORT after five minutes.
* Report not visible: worker and dashboard must use the same RACKGUARD_ANALYSIS_FILE. Restart the dashboard only if you changed that setting. Missing report stays UNAVAILABLE; failures do not fabricate analysis.

## What to tell judges

“Our server verifies the telemetry first. Gemini then summarizes filtered observations and suggests checks for the operator. It cannot unlock doors, authorize devices, or change security rules. If Gemini is unavailable, deterministic security checks and sensor collection continue.”

No threshold is invented for the data centre; configure and validate physical thresholds separately. An LLM explanation is not proof of an attack, a sensor's accuracy, or a human/robot identity.

## Validation and sources

Tests use mocked Google responses; a live API call must be checked on your VM with your private key. No real Gemini account call was made while building the add-on.

Uses Google's documented generateContent endpoint and x-goog-api-key authentication:
https://ai.google.dev/api/generate-content
https://ai.google.dev/api
