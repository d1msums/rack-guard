"""Optional one-shot local Ollama analysis. Never grants access or changes trust state."""
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import requests
from dashboard import settings, read_snapshot
from security import load_public


def main():
    options = settings()
    model = os.environ.get('OLLAMA_MODEL', '').strip()
    if not model:
        raise SystemExit('Set OLLAMA_MODEL in .env to an installed local Ollama model')
    config = json.loads(Path(options['config']).expanduser().read_text())
    keys = {device: load_public(entry['signing_public_key']) for device, entry in config['devices'].items()}
    snapshot = read_snapshot(config, keys, 100)
    if not snapshot['events']:
        raise SystemExit('No signature-verified events available for analysis')
    # Only numeric/boolean/time context; no card aliases or arbitrary event text in the prompt.
    data = [{'event_type': event['event_type'], 'timestamp': event['timestamp'],
             'temperature_c': event['data'].get('temperature_c'),
             'access_granted': event.get('access_granted'), 'simulated': event['simulated']}
            for event in snapshot['events']]
    prompt = ('You are an advisory data-centre telemetry analyst. Summarize only the supplied observations. '
              'Distinguish simulated readings. Do not infer a replay attack from repeating temperatures or '
              'regular sampling. Do not claim cryptography failure or a human/robot identity. State limits '
              'and suggest checks. No action is executed. Use plain text, at most 250 words. Data:\n' + json.dumps(data))
    with requests.Session() as session:
        session.trust_env = False
        with session.post('http://127.0.0.1:11434/api/generate', json={
                'model': model, 'prompt': prompt, 'stream': False,
                'options': {'num_predict': 500}}, timeout=(5, 120), stream=True,
                allow_redirects=False) as response:
            response.raise_for_status()
            payload = bytearray()
            for chunk in response.iter_content(4096):
                payload.extend(chunk)
                if len(payload) > 65536:
                    raise ValueError('Model response too large')
            output = json.loads(payload)
    summary = output.get('response')
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError('No analysis text returned')
    report = {'model': model, 'summary': summary[:16000],
              'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'events_analyzed': len(data), 'last_event_id': snapshot['events'][-1]['event_id']}
    target = Path(options['analysis_file']).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent, delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(report, handle)
    os.replace(temporary, target)
    print(f'Analysis saved for {len(data)} events. Advisory only.')


if __name__ == '__main__':
    main()
