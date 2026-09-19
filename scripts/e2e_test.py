import urllib.request, json, time

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
    except Exception as ex:
        return {'error': str(ex)}, 0

# Login
r, s = api('POST', '/auth/login', body={'username':'admin','password':'Admin@123'})
token = r['data']['token']
print('[1] Login OK')

# Upload dataset via multipart
boundary = 'AaBbCcDdEe'
csv_path = 'dataset/sample/sample_nids_data.csv'
with open(csv_path, 'rb') as f:
    file_bytes = f.read()

disp = 'Content-Disposition: form-data; name="file"; filename="sample_nids_data.csv"'
body_b = (
    ('--' + boundary + '\r\n').encode() +
    (disp + '\r\n').encode() +
    b'Content-Type: text/csv\r\n\r\n' +
    file_bytes +
    ('\r\n--' + boundary + '--\r\n').encode()
)

req = urllib.request.Request(
    BASE + '/datasets/upload',
    data=body_b,
    headers={
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'multipart/form-data; boundary=' + boundary
    },
    method='POST'
)
try:
    resp = urllib.request.urlopen(req)
    upload_r = json.loads(resp.read())
    dataset_id = upload_r.get('data', {}).get('dataset_id', '')
    print('[2] Dataset upload: success=' + str(upload_r.get('success')) + ', id=' + str(dataset_id))
    stats = upload_r.get('data', {}).get('stats', {})
    print('    Rows: ' + str(stats.get('total_rows')) + ', Features: ' + str(stats.get('recognized_features')))
except urllib.error.HTTPError as e:
    d = json.loads(e.read())
    print('[2] Dataset upload FAILED: ' + str(d))
    exit(1)

# Train model
print('[3] Starting model training (Decision Tree)...')
t0 = time.time()
r, s = api('POST', '/models/train', token=token, body={
    'dataset_id': dataset_id,
    'model_type': 'decision_tree',
    'test_size': 0.2
})
t1 = time.time()
print('    Training: success=' + str(r.get('success')) + ', time=' + str(round(t1-t0, 1)) + 's')
if r.get('success'):
    metrics = r['data']['metrics']
    model_id = r['data']['model_db_id']
    print('    Accuracy: ' + str(round(metrics['accuracy'], 4)))
    print('    F1-weighted: ' + str(round(metrics['f1_weighted'], 4)))
    print('    F1-macro: ' + str(round(metrics['f1_macro'], 4)))
    print('    Model ID: ' + str(model_id))
else:
    print('    FAIL: ' + str(r.get('message')))
    exit(1)

# Activate
r, s = api('POST', '/models/' + model_id + '/activate', token=token)
print('[4] Activate: ' + str(r.get('message')))

# Single prediction
features = {
    'Flow Duration': 0.0, 'Total Fwd Packets': 1, 'Total Backward Packets': 0,
    'Total Length of Fwd Packets': 0, 'Total Length of Bwd Packets': 0,
    'Fwd Packet Length Max': 0, 'Fwd Packet Length Min': 0,
    'Fwd Packet Length Mean': 0, 'Fwd Packet Length Std': 0,
    'Bwd Packet Length Max': 0, 'Bwd Packet Length Min': 0,
    'Bwd Packet Length Mean': 0, 'Bwd Packet Length Std': 0,
    'Flow Bytes/s': 0, 'Flow Packets/s': 0,
    'Flow IAT Mean': 0, 'Flow IAT Std': 0, 'Flow IAT Max': 0, 'Flow IAT Min': 0,
    'Fwd IAT Total': 0, 'Fwd IAT Mean': 0, 'Fwd IAT Std': 0,
    'Fwd IAT Max': 0, 'Fwd IAT Min': 0,
    'Bwd IAT Total': 0, 'Bwd IAT Mean': 0, 'Bwd IAT Std': 0,
    'Bwd IAT Max': 0, 'Bwd IAT Min': 0,
    'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0,
    'Fwd Header Length': 20, 'Bwd Header Length': 0,
    'Fwd Packets/s': 0, 'Bwd Packets/s': 0,
    'Min Packet Length': 0, 'Max Packet Length': 0,
    'Packet Length Mean': 0, 'Packet Length Std': 0, 'Packet Length Variance': 0,
    'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 0,
    'PSH Flag Count': 0, 'ACK Flag Count': 0, 'URG Flag Count': 0,
    'CWE Flag Count': 0, 'ECE Flag Count': 0,
    'Down/Up Ratio': 0, 'Average Packet Size': 0, 'Avg Fwd Segment Size': 0,
    'Avg Bwd Segment Size': 0, 'Fwd Header Length.1': 20,
    'Subflow Fwd Packets': 1, 'Subflow Fwd Bytes': 0,
    'Subflow Bwd Packets': 0, 'Subflow Bwd Bytes': 0,
    'Init_Win_bytes_forward': 8192, 'Init_Win_bytes_backward': 0,
    'act_data_pkt_fwd': 0, 'min_seg_size_forward': 20,
    'Active Mean': 0, 'Active Std': 0, 'Active Max': 0, 'Active Min': 0,
    'Idle Mean': 0, 'Idle Std': 0, 'Idle Max': 0, 'Idle Min': 0,
}
r, s = api('POST', '/predict', token=token, body={
    'features': features,
    'source_ip': '192.168.1.100',
    'destination_ip': '10.0.0.1',
    'source_port': 54321,
    'destination_port': 80,
    'protocol': 'TCP'
})
pred_data = r.get('data', {})
print('[5] Single predict: prediction=' + str(pred_data.get('prediction')) + ', severity=' + str(pred_data.get('severity')) + ', confidence=' + str(pred_data.get('confidence')) + ', is_intrusion=' + str(pred_data.get('is_intrusion')))

# Verify detection stored
r, s = api('GET', '/detections', token=token)
print('[6] Detections in DB: ' + str(r['data']['total']))

# Verify alerts
r, s = api('GET', '/alerts', token=token)
print('[7] Alerts in DB: ' + str(r['data']['total']))

# Dashboard
r, s = api('GET', '/dashboard/summary', token=token)
d = r['data']
am = d.get('active_model') or {}
print('[8] Dashboard summary:')
print('    total_traffic=' + str(d['total_traffic']))
print('    intrusions=' + str(d['intrusion_count']))
print('    detection_rate=' + str(d['detection_rate']))
print('    active_model=' + str(am.get('version')))
print('    model_accuracy=' + str(am.get('accuracy')))

# Analytics
r, s = api('GET', '/analytics/overview', token=token)
print('[9] Analytics overview keys: ' + str(list(r.get('data', {}).keys())))

# Reports preview
r, s = api('GET', '/reports/preview', token=token)
rp = r.get('data', {})
print('[10] Report preview: total_traffic=' + str(rp.get('total_traffic')) + ', attack_cats=' + str(list(rp.get('attack_categories', {}).keys())))

print('\n=== ALL CHECKS DONE ===')
