"""Required mTLS with client-certificate pinning bound to enrolled device IDs."""
import hashlib
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import requests
from werkzeug.serving import WSGIRequestHandler, make_server

def expanded(path):
    return str(Path(path).expanduser())

def server_context(config):
    tls = config['tls']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(expanded(tls['cert']), expanded(tls['key']))
    context.load_verify_locations(cafile=expanded(tls['ca']))
    context.verify_mode = ssl.CERT_REQUIRED
    return context

class PeerHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        certificate = self.connection.getpeercert(binary_form=True)
        if certificate:
            # Set from the TLS socket, never from a client-supplied HTTP header.
            environ['rackguard.peer_sha256'] = hashlib.sha256(certificate).hexdigest()
        return environ

def build_server(config, app, host='0.0.0.0', port=18443):
    return make_server(host, port, app, threaded=True,
                       ssl_context=server_context(config), request_handler=PeerHandler)

def client_session(config):
    url = urlsplit(config['server_url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('server_url must be HTTPS, without embedded credentials')
    tls = config['tls']
    session = requests.Session()
    session.trust_env = False
    session.verify = expanded(tls['ca'])
    session.cert = (expanded(tls['cert']), expanded(tls['key']))
    return session
