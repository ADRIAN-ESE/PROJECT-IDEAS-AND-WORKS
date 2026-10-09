"""Smoke test for the PhishGuard backend (run: python tests/smoke_test.py).

Uses an isolated temporary database so the demo dataset is untouched.
"""
import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# isolate from the live database before the app imports storage
_tmpdir = tempfile.mkdtemp(prefix="phishguard-test-")
os.environ["PHISHGUARD_DB"] = str(Path(_tmpdir) / "test.db")

import app as A  # noqa: E402

c = A.app.test_client()

# 1. analyze with TI-matching IP
r = c.post('/api/analyze', json={
    'sender': 'PayPal <alerts@paypa1.xyz>',
    'subject': 'URGENT verify your account',
    'body': 'Click http://192.0.2.55/login to verify your password now, credit card required',
    'headers': 'Authentication-Results: spf=fail\r\nReceived: from x (192.0.2.55)\r\nReply-To: steal@evil.ru',
    'attachments': 'update.exe'})
d = r.get_json()
print('analyze:', r.status_code, d['score'], d['verdict'], 'iocs', d['iocs']['counts'],
      'ti', len(d['threat_intel']['matches']), 'scan', d['scan_id'])
print('  header findings:', [f['title'] for f in d['findings'] if f['category'] == 'headers'][:6])

# 2. eml parse
eml = (b'From: Security <alert@micros0ft-support.xyz>\r\n'
       b'To: victim@example.com\r\n'
       b'Reply-To: helpdesk@evil.example\r\n'
       b'Subject: Action required\r\n'
       b'Date: Mon, 5 Oct 2026 03:12:00 +0000\r\n'
       b'Message-ID: <abc@evil.example>\r\n'
       b'MIME-Version: 1.0\r\n'
       b'Content-Type: multipart/mixed; boundary=B\r\n\r\n'
       b'--B\r\nContent-Type: text/plain\r\n\r\n'
       b'Verify your account immediately at http://203.0.113.9/x\n'
       b'--B\r\nContent-Type: application/octet-stream; name=invoice.zip\r\n'
       b'Content-Transfer-Encoding: base64\r\n\r\n'
       b'UEsDBAoAAAAA\r\n'
       b'--B--\r\n')
r = c.post('/api/parse-eml', data={'file': (io.BytesIO(eml), 'phish.eml')},
           content_type='multipart/form-data')
p = r.get_json()
print('parse-eml:', r.status_code, repr(p['sender'])[:55], '| att:', p['attachments'],
      '| hashes:', len(p['attachment_hashes']))
r2 = c.post('/api/analyze', json={k: p[k] for k in
                                  ('sender', 'subject', 'body', 'headers',
                                   'attachments', 'attachment_hashes')})
d2 = r2.get_json()
print('  eml analyze:', d2['score'], d2['verdict'],
      'ti:', [m['indicator'] for m in d2['threat_intel']['matches']],
      'hash iocs:', d2['iocs']['counts']['hashes'])

# 3. activity
logins = [
    {'ts': '2026-10-07T02:10:00', 'user': 'a@x.com', 'ip': '203.0.113.9', 'geo': 'NG', 'device': 'chrome', 'success': True},
    {'ts': '2026-10-07T02:40:00', 'user': 'a@x.com', 'ip': '203.0.113.9', 'geo': 'NG', 'device': 'chrome', 'success': True},
    {'ts': '2026-10-07T01:00:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': False},
    {'ts': '2026-10-07T01:05:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': False},
    {'ts': '2026-10-07T01:10:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': False},
    {'ts': '2026-10-07T01:15:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': False},
    {'ts': '2026-10-07T01:20:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': False},
    {'ts': '2026-10-07T01:25:00', 'user': 'a@x.com', 'ip': '198.51.100.7', 'geo': 'US', 'device': 'UnknownBox', 'success': True},
]
emails = [{'ts': '2026-10-07T03:00:00', 'from': 'a@x.com',
           'recipients': [f'u{i}@ext.com' for i in range(40)], 'subject': 'FYI'}]
r = c.post('/api/activity', json={'logins': logins, 'emails': emails})
a = r.get_json()
print('activity:', r.status_code, a['score'], a['verdict'], len(a['findings']), 'findings:',
      [f['title'] for f in a['findings']])

# 4. takeover
r = c.post('/api/takeover', json={'indicators': ['forwarding_rule', 'unknown_session', 'mfa_disabled']})
t = r.get_json()
print('takeover:', r.status_code, t['score'], t['verdict'], len(t['findings']))

# 5. dashboard data
print('stats:', c.get('/api/stats').get_json())
inc = c.get('/api/incidents').get_json()
print('incidents:', len(inc), [i['kind'] for i in inc])
al = c.get('/api/alerts').get_json()
print('alerts:', [(x['severity'], x['status']) for x in al])

# 6. feedback + alert status
sid = inc[0]['id']
print('feedback:', c.post('/api/feedback', json={'incident_id': sid, 'label': 'tp'}).status_code)
first_alert = al[0]['id']
print('alert patch:', c.patch(f'/api/alerts/{first_alert}',
                              json={'status': 'acknowledged'}).status_code)

# 7. TI check + watchlist
ti = c.post('/api/ti/check', json={'indicators': 'coinhive.com, 192.0.2.55, benign.org'}).get_json()
print('ti:', [(m['indicator'], m['category']) for m in ti['matches']])
print('ti add:', c.post('/api/ti/add', json={'indicator': 'evil-paypal.xyz'}).status_code,
      'watch:', len(c.get('/api/watchlist').get_json()))
sub = c.post('/api/ti/check', json={'indicators': 'sub.evil-paypal.xyz'}).get_json()
print('watchlist match:', [m['indicator'] for m in sub['matches']])
print('iocs:', [(i['value'], i['type'], i['flagged']) for i in c.get('/api/iocs').get_json()['iocs'][:4]])

# 8. edge cases
print('empty analyze:', c.post('/api/analyze', json={'sender': '', 'body': ''}).status_code)
print('bad eml:', c.post('/api/parse-eml', data={'file': (io.BytesIO(b'\x00\x01\x02'), 'x.bin')},
                         content_type='multipart/form-data').status_code)
print('health:', c.get('/api/health').get_json())
