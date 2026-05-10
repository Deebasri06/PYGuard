import time

# Tracks TCP connection states
# Key: (src_ip, dst_ip, dst_port), Value: state info
_connections = {}

TCP_STATES = ['SYN_SENT', 'ESTABLISHED', 'FIN_WAIT', 'CLOSED']

def update_state(src_ip, dst_ip, dst_port, flags):
    """
    Update TCP connection state based on flags.
    flags: string like 'S' (SYN), 'SA' (SYN-ACK), 'A' (ACK), 'F' (FIN), 'R' (RST)
    """
    key = (src_ip, dst_ip, dst_port)

    if 'S' in flags and 'A' not in flags:
        # SYN — new connection attempt
        _connections[key] = {
            'state': 'SYN_SENT',
            'start_time': time.time(),
            'last_seen': time.time()
        }
    elif 'S' in flags and 'A' in flags:
        # SYN-ACK — server responding
        if key in _connections:
            _connections[key]['state'] = 'SYN_ACK'
            _connections[key]['last_seen'] = time.time()
    elif 'A' in flags and key in _connections:
        # ACK — connection established
        _connections[key]['state'] = 'ESTABLISHED'
        _connections[key]['last_seen'] = time.time()
    elif 'F' in flags and key in _connections:
        # FIN — connection closing
        _connections[key]['state'] = 'FIN_WAIT'
        _connections[key]['last_seen'] = time.time()
    elif 'R' in flags and key in _connections:
        # RST — connection reset
        _connections[key]['state'] = 'CLOSED'
        _connections[key]['last_seen'] = time.time()

def get_connections():
    return dict(_connections)

def get_active_count():
    return sum(1 for v in _connections.values() if v['state'] == 'ESTABLISHED')

def cleanup_old(timeout=120):
    """Remove connections not seen in timeout seconds."""
    now = time.time()
    to_delete = [k for k, v in _connections.items() if now - v['last_seen'] > timeout]
    for k in to_delete:
        del _connections[k]
        