import urllib.request, json, threading, time

BASE = 'http://localhost:5000'
def api(method, path, token=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

# Login
r, s = api('POST', '/auth/login', body={'username':'admin','password':'Admin@123'})
token = r['data']['token']
print('Login OK, token acquired')

# Simulate what the dashboard does: fire 6 concurrent requests with same token
results = {}

def fetch(name, path):
    r, s = api('GET', path, token=token)
    results[name] = (s, r.get('success'))

threads = [
    threading.Thread(target=fetch, args=('summary', '/dashboard/summary')),
    threading.Thread(target=fetch, args=('trends', '/dashboard/trends')),
    threading.Thread(target=fetch, args=('me', '/auth/me')),
    threading.Thread(target=fetch, args=('overview', '/analytics/overview')),
    threading.Thread(target=fetch, args=('attacks', '/analytics/attacks')),
    threading.Thread(target=fetch, args=('alerts', '/alerts')),
]

for t in threads: t.start()
for t in threads: t.join()

print('Concurrent request results:')
all_ok = True
for name, (status, success) in results.items():
    ok = status == 200 and success
    label = 'PASS' if ok else 'FAIL'
    print('  [' + label + '] ' + name + ': status=' + str(status) + ', success=' + str(success))
    if not ok:
        all_ok = False

print()
print('Result:', 'ALL PASS - login redirect bug is fixed!' if all_ok else 'STILL FAILING')
