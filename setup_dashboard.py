"""Create a local operator password hash without printing or storing the password."""
import getpass
import os
from pathlib import Path
from werkzeug.security import generate_password_hash

if __name__ == '__main__':
    password = getpass.getpass('New dashboard password (at least 12 characters): ')
    if len(password) < 12 or password != getpass.getpass('Repeat password: '):
        raise SystemExit('Password too short or passwords did not match')
    path = Path(__file__).resolve().parent / '.env'
    current = path.read_text() if path.exists() else ''
    lines = [line for line in current.splitlines() if not line.startswith('DASHBOARD_PASSWORD_HASH=')]
    lines.append('DASHBOARD_PASSWORD_HASH=' + generate_password_hash(password))
    temp = path.with_suffix('.env-new')
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write('\n'.join(lines) + '\n')
    os.replace(temp, path)
    print('Operator password hash saved in .env. Username defaults to operator.')
