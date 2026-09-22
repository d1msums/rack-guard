"""Generate local keys/CSRs and sign them on a separate certificate authority.

Private keys are never printed or overwritten. Run request commands on the
target device so its private keys never need to leave that device.
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def folder(path):
    result = Path(path).expanduser()
    result.mkdir(parents=True, exist_ok=True, mode=0o700)
    return result

def write_new(path, content, private=False):
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)

def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())

def name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])

def ca_init(directory):
    directory = folder(directory)
    if any((directory / item).exists() for item in ('ca.key', 'ca.crt')):
        raise FileExistsError('CA files already exist; keep them, do not regenerate')
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name('RackGuard demo CA'))
            .issuer_name(name('RackGuard demo CA')).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False,
                                       True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))
    write_new(directory / 'ca.key', private_bytes(key), True)
    write_new(directory / 'ca.crt', cert.public_bytes(serialization.Encoding.PEM))

def make_request(directory, role, device_id='coldguard-pi-01'):
    directory = folder(directory)
    expected = ['tls.key', 'request.csr']
    if role == 'pi':
        expected += ['signing.key', 'signing.pub']
    if any((directory / item).exists() for item in expected):
        raise FileExistsError('Request/key files already exist; do not overwrite them')
    # TLS uses a separate P-256 key; payload signatures use Ed25519.
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        name(device_id if role == 'pi' else 'rackguard-vm')).sign(key, hashes.SHA256())
    write_new(directory / 'tls.key', private_bytes(key), True)
    write_new(directory / 'request.csr', csr.public_bytes(serialization.Encoding.PEM))
    if role == 'pi':
        signing = ed25519.Ed25519PrivateKey.generate()
        write_new(directory / 'signing.key', private_bytes(signing), True)
        write_new(directory / 'signing.pub', signing.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def issue(ca_dir, csr_file, output, role, server_ip='172.16.40.10'):
    ca_dir = Path(ca_dir).expanduser()
    ca_key = serialization.load_pem_private_key((ca_dir / 'ca.key').read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
    csr = x509.load_pem_x509_csr(Path(csr_file).expanduser().read_bytes())
    if not csr.is_signature_valid:
        raise ValueError('CSR signature invalid')
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject)
               .public_key(csr.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=2))
               .not_valid_after(now + datetime.timedelta(days=7))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
               .add_extension(x509.KeyUsage(True, False, False, False, False,
                                          False, False, False, False), True)
               .add_extension(x509.ExtendedKeyUsage([
                   ExtendedKeyUsageOID.CLIENT_AUTH if role == 'pi'
                   else ExtendedKeyUsageOID.SERVER_AUTH]), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False))
    if role == 'vm':
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address(server_ip))]), False)
    cert = builder.sign(ca_key, hashes.SHA256())
    output = Path(output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    write_new(output, cert.public_bytes(serialization.Encoding.PEM))
    return cert

def fingerprint(path):
    return x509.load_pem_x509_certificate(Path(path).expanduser().read_bytes()).fingerprint(hashes.SHA256()).hex()

def configure(role, config_path, client_cert=None):
    # Preserve card enrollment/state settings when updating an existing config.
    path = Path(config_path).expanduser()
    template = Path(__file__).parent / f'config.{role}.example.json'
    config = json.loads(template.read_text())
    if path.exists():
        old = json.loads(path.read_text())
        for field in ('log_dir', 'authorized_cards', 'device_id', 'rfid_key_path'):
            if field in old:
                config[field] = old[field]
        backup = path.with_name(path.name + '.before-mtls')
        write_new(backup, path.read_bytes(), True)
    if role == 'vm':
        if not client_cert:
            raise ValueError('VM configuration needs --client-cert')
        config['devices']['coldguard-pi-01']['tls_fingerprint_sha256'] = fingerprint(client_cert)
    temporary = path.with_name(path.name + '.new')
    write_new(temporary, (json.dumps(config, indent=2) + '\n').encode(), True)
    os.replace(temporary, path)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    ca = sub.add_parser('ca'); ca.add_argument('--dir', required=True)
    req = sub.add_parser('request'); req.add_argument('--role', choices=['pi','vm'], required=True)
    req.add_argument('--dir', required=True)
    sign = sub.add_parser('sign'); sign.add_argument('--role', choices=['pi','vm'], required=True)
    sign.add_argument('--ca-dir', required=True); sign.add_argument('--csr', required=True)
    sign.add_argument('--out', required=True); sign.add_argument('--server-ip', default='172.16.40.10')
    fp = sub.add_parser('fingerprint'); fp.add_argument('cert')
    cfg = sub.add_parser('configure'); cfg.add_argument('--role', choices=['pi','vm'], required=True)
    cfg.add_argument('--config', default='config.json'); cfg.add_argument('--client-cert')
    args = parser.parse_args()
    if args.command == 'ca': ca_init(args.dir)
    elif args.command == 'request': make_request(args.dir, args.role)
    elif args.command == 'sign': issue(args.ca_dir, args.csr, args.out, args.role, args.server_ip)
    elif args.command == 'fingerprint': print(fingerprint(args.cert))
    else: configure(args.role, args.config, args.client_cert)
    if args.command != 'fingerprint': print('Done. Private keys were not printed.')

if __name__ == '__main__': main()
