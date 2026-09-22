"""Privately configure Gemini without overwriting dashboard login settings."""
import getpass
import os
from pathlib import Path
import re
import tempfile

if __name__ == '__main__':
    path = Path(__file__).resolve().parent / '.env'
    key = getpass.getpass('Paste Gemini API key (hidden): ').strip()
    if not key or any(c.isspace() for c in key) or not key.isascii():
        raise SystemExit('Invalid key format; nothing changed')
    model = input('Gemini model [gemini-flash-latest]: ').strip() or 'gemini-flash-latest'
    if not re.fullmatch(r'[A-Za-z0-9._-]+', model):
        raise SystemExit('Invalid model name; nothing changed')
    current = path.read_text(encoding='utf-8-sig') if path.exists() else ''
    lines = [line for line in current.splitlines()
             if line.partition('=')[0].strip() not in ('GEMINI_API_KEY', 'GEMINI_MODEL')]
    lines.extend(['GEMINI_API_KEY=' + key, 'GEMINI_MODEL=' + model])
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        f.write('\n'.join(lines) + '\n')
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    print('Gemini settings saved privately. Dashboard password unchanged. Do not commit .env.')
