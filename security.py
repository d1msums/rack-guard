"""Ed25519 message signatures; separate HMAC only for local RFID pseudonyms."""
import base64
import binascii
import hashlib
import hmac
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b'RackGuard:event:v1\x00'

def load_private(path):
    key = serialization.load_pem_private_key(Path(path).expanduser().read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Expected an Ed25519 private key')
    return key

def load_public(path):
    key = serialization.load_pem_public_key(Path(path).expanduser().read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Expected an Ed25519 public key')
    return key

def generate_signature(private_key, payload_bytes):
    return base64.b64encode(private_key.sign(DOMAIN + payload_bytes)).decode('ascii')

def verify_signature(public_key, payload_bytes, signature):
    if not isinstance(signature, str) or len(signature) != 88:
        return False
    try:
        decoded = base64.b64decode(signature, validate=True)
        if len(decoded) != 64:
            return False
        public_key.verify(decoded, DOMAIN + payload_bytes)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False

def load_rfid_secret(path):
    key = bytes.fromhex(Path(path).expanduser().read_text().strip())
    if len(key) != 32:
        raise ValueError('RFID key must contain 32 bytes encoded as hex')
    return key

def rfid_token(key, uid):
    # Preserve previous token format/enrollments; this is NOT message signing.
    return 'token-' + hmac.new(key, uid.encode('utf-8'), hashlib.sha256).hexdigest()[:12]
