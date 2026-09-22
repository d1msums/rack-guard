# Complete v8 validation

Combined suite: 44 tests passed in 19.355 seconds locally. Includes 35 existing tests, 6 mocked Gemini tests and 3 access-result tests. Physical LED/LCD behavior and live network deployment were not tested in this run. Prior results follow.

# Verification record

## Security Alerts v7

2026-09-20: `python -m unittest -v test_security test_mtls test_dashboard test_alerts` passed **35 tests in 17.405 seconds** locally. This includes all prior tests plus end-to-end receiver rejection logging to the authenticated alerts API, bounded reads, missing/unreadable log states, stable alert IDs, partial/malformed records, log rotation and fixed severity/description mapping. No real Pi or VM was used in this run.

## Dashboard integration v6

2026-09-20: `python -m unittest -v test_security test_mtls test_dashboard` passed **29 tests in 17.103 seconds** locally, including all 19 original trust tests and 10 dashboard/analysis integration tests. The optional model-worker test uses a mocked Ollama response, not a live model.

Headless Microsoft Edge (Playwright) also passed: authenticated page load, supplied background image, simulated signed temperature/RFID records, all four tabs, temperature chart, unavailable-model status, integrity counts and mobile layout. No JavaScript page errors were recorded. Preview data is disposable and explicitly labelled simulated.

This is a local test result. The updated dashboard has not been deployed to the user's VM, and no real LLM inference has been run. Existing certificate, replay, rate and database controls remain covered by the original suite below.

Date: 2026-09-20 (Asia/Kuala_Lumpur)

Command:

```text
python -m unittest -v test_security test_mtls
```

Result: **19 tests passed in 4.743 seconds** on the local development machine. Python syntax compilation also passed for the sender, receiver, security, transport, database verifier and provisioning modules.

Verified behaviors:

- valid mTLS plus Ed25519 event accepted once;
- exact replay rejected;
- missing client certificate rejected before the application received a request;
- client certificate from an untrusted CA rejected before application dispatch;
- a different CA-valid client certificate cannot claim the enrolled Pi identity;
- wrong Ed25519 signing key rejected;
- signed bytes modified after signing rejected;
- incorrect server CA rejected;
- server hostname mismatch rejected;
- HTTP configuration rejected with no downgrade fallback;
- unsupported sensor methods, oversized payloads and excess request rates rejected;
- unsigned database injection blocked and signed-row modification detected;
- stale/future messages, malformed input and invalid fields rejected;
- counter persistence and migration verified;
- receiver restart continues to reject replay;
- concurrent duplicate handling verified;
- database transaction rollback behavior verified;
- RFID alias/export behavior and key permissions verified.

These are local disposable-certificate tests. The Pi and Rocky Linux VM still require deployment and a final live test before claiming the upgrade is operational in the hackathon environment.

V7 browser verification: headless Microsoft Edge, all five tabs passed with no JavaScript errors. Verified invalid-signature alert, visible banner, dismissal without repeat notification on the next poll, signed temperature/RFID display, charts, unavailable analysis state, and mobile layout. Used temporary local data, not the deployed Pi/VM.
