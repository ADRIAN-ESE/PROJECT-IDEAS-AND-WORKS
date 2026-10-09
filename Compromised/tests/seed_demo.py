"""Seed the database with a small, clean demo dataset for first run.

Usage:  python tests/seed_demo.py          (wipes and reseeds data/phishguard.db)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import app as A  # noqa: E402  (initialises storage)
import storage    # noqa: E402

# start from a clean slate (delete rows rather than the file — the running
# server may still hold the database open on Windows)
storage.init_db()
with storage._connect() as conn, storage._lock:
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM custom_iocs")

c = A.app.test_client()

# --- 1. phishing email -----------------------------------------------------
phish = c.post('/api/analyze', json={
    'sender': 'PayPal Security <alerts@secure-verify-paypal.xyz>',
    'subject': 'URGENT: your account will be suspended in 24 hours',
    'body': (
        'Dear Customer,\n\nWe detected unusual activity. Your account will be suspended '
        'within 24 hours unless you verify immediately.\n\n'
        'Click here to verify: http://203.0.113.44/paypal-secure/login.php\n\n'
        'Please confirm your password and provide your credit card number to restore access.\n\n'
        'Thank you,\nPayPal Customer Care'),
    'headers': ('Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail\n'
                'Received: from unknown (203.0.113.44)\n'
                'Reply-To: recovery@attacker-mail.ru'),
    'attachments': 'invoice_2026.zip, update.exe',
}).get_json()
c.post('/api/feedback', json={'incident_id': phish['scan_id'], 'label': 'tp'})

# --- 2. legitimate email ---------------------------------------------------
legit = c.post('/api/analyze', json={
    'sender': 'Jane Doe <jane.doe@northwind-co.com>',
    'subject': "Notes from today's design review",
    'body': ('Hi Sam,\n\nThanks for the thoughtful review this afternoon. I have attached '
             'the updated mockups.\n\nCould you take a look before Thursday? '
             'Ping me on Teams if anything is unclear.\n\nBest,\nJane'),
    'headers': 'Authentication-Results: mx.northwind-co.com; spf=pass dkim=pass dmarc=pass',
    'attachments': 'mockups_v3.pdf',
}).get_json()

# --- 3. suspicious login / sending activity --------------------------------
activity = c.post('/api/activity', json={
    'logins': [
        {'ts': '2026-10-07T09:12:00', 'user': 'j.doe@northwind-co.com', 'ip': '198.51.100.20',
         'geo': 'DE', 'device': 'Corp-Laptop-14', 'success': True},
        {'ts': '2026-10-07T13:45:00', 'user': 'j.doe@northwind-co.com', 'ip': '198.51.100.20',
         'geo': 'DE', 'device': 'Corp-Laptop-14', 'success': True},
        {'ts': '2026-10-07T23:48:00', 'user': 'j.doe@northwind-co.com', 'ip': '203.0.113.77',
         'geo': 'NG', 'device': 'UnknownBrowser', 'success': False},
        {'ts': '2026-10-07T23:51:00', 'user': 'j.doe@northwind-co.com', 'ip': '203.0.113.77',
         'geo': 'NG', 'device': 'UnknownBrowser', 'success': False},
        {'ts': '2026-10-07T23:53:00', 'user': 'j.doe@northwind-co.com', 'ip': '203.0.113.77',
         'geo': 'NG', 'device': 'UnknownBrowser', 'success': False},
        {'ts': '2026-10-07T23:55:00', 'user': 'j.doe@northwind-co.com', 'ip': '203.0.113.77',
         'geo': 'NG', 'device': 'UnknownBrowser', 'success': False},
        {'ts': '2026-10-07T23:58:00', 'user': 'j.doe@northwind-co.com', 'ip': '203.0.113.77',
         'geo': 'NG', 'device': 'UnknownBrowser', 'success': True},
        {'ts': '2026-10-08T00:30:00', 'user': 'j.doe@northwind-co.com', 'ip': '192.0.2.140',
         'geo': 'US', 'device': 'Chrome/Unknown', 'success': True},
    ],
    'emails': [
        {'ts': '2026-10-08T00:45:00', 'from': 'j.doe@northwind-co.com',
         'recipients': [f'client{i}@external.example' for i in range(35)],
         'subject': 'Updated invoice'},
    ],
}).get_json()

# --- 4. takeover assessment ------------------------------------------------
takeover = c.post('/api/takeover', json={
    'indicators': ['forwarding_rule', 'unknown_session', 'mfa_disabled'],
}).get_json()

# --- watchlist example -----------------------------------------------------
c.post('/api/ti/add', json={'indicator': 'secure-verify-paypal.xyz',
                            'note': 'Phishing kit host observed 2026-10-08'})

print("Seeded incidents:")
for row in storage.list_incidents():
    print(f"  [{row['kind']:8}] {row['score']:>3} {row['verdict']:<15} {row['title'][:50]}")
print("Alerts:", [(a['severity'], a['status']) for a in storage.list_alerts()])
print("Stats :", storage.stats())
