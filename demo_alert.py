"""Run on the enrolled Pi: send ONE modified-signature test. No sequence reset."""
import datetime as dt
import json
import os
import uuid
from security import load_private, generate_signature
from counter import get_next_sequence
from transport import client_session

if __name__ == '__main__':
    with open(os.environ.get('COLDGUARD_CONFIG','config.json')) as handle:
        config=json.load(handle)
    key=load_private(config['signing_private_key'])
    sequence=get_next_sequence(os.path.join(os.path.expanduser(config.get('log_dir','~/.local/state/coldguard')),'pi_state.db'))
    event={'device_id':config['device_id'],'event_id':str(uuid.uuid4()),'sequence':sequence,
           'timestamp':dt.datetime.now(dt.timezone.utc).isoformat(),'event_type':'temperature',
           'simulated':True,'data':{'temperature_c':23.1}}
    raw=json.dumps(event,separators=(',',':'),sort_keys=True).encode()
    signature=generate_signature(key,raw)
    event['data']['temperature_c']=99.9
    modified=json.dumps(event,separators=(',',':'),sort_keys=True).encode()
    with client_session(config) as session:
        response=session.post(config['server_url'],data=modified,
            headers={'Content-Type':'application/json','X-Device-ID':config['device_id'],'X-Signature':signature},
            timeout=5,allow_redirects=False)
    print('HTTP',response.status_code,response.text)
    if response.status_code != 403 or response.json().get('reason') != 'BAD_AUTHENTICATION':
        raise SystemExit('Test did not produce expected rejection. Check connection/config or wait if rate limited.')
    print('PASS: modified message rejected. Open Security Alerts; expect Invalid message signature within the next poll.')
