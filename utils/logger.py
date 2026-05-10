import json
import os
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs.json')

def log_packet(src_ip, dst_ip, protocol, dst_port, action, reason):
    entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'dst_port': dst_port,
        'action': action,
        'reason': reason
    }
    _append_log(entry)
    return entry

def log_alert(src_ip, alert_msg):
    entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': 'ALERT',
        'src_ip': src_ip,
        'message': alert_msg
    }
    _append_log(entry)
    return entry

def _append_log(entry):
    logs = read_logs()
    logs.append(entry)
    # Keep last 500 entries only
    logs = logs[-500:]
    with open(LOG_PATH, 'w') as f:
        json.dump(logs, f, indent=2)

def read_logs():
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, 'r') as f:
        try:
            return json.load(f)
        except:
            return []

def clear_logs():
    with open(LOG_PATH, 'w') as f:
        json.dump([], f)
        