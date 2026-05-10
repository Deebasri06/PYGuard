import time
from collections import defaultdict
from core.rules_engine import block_ip

# Track port access per IP for scan detection
_port_access = defaultdict(list)   # ip -> [(port, timestamp), ...]
_syn_counts = defaultdict(list)    # ip -> [timestamp, ...]

def inspect(src_ip, dst_port, flags, settings):
    """
    Inspect a packet for threats.
    Returns list of alert strings (empty if no threats).
    """
    alerts = []
    now = time.time()
    window = settings.get('scan_window_seconds', 10)
    scan_thresh = settings.get('scan_threshold', 15)
    syn_thresh = settings.get('syn_flood_threshold', 100)
    
    # --- Port Scan Detection ---
    _port_access[src_ip].append((dst_port, now))
    # Keep only entries within the time window
    _port_access[src_ip] = [(p, t) for p, t in _port_access[src_ip] if now - t <= window]
    unique_ports = set(p for p, t in _port_access[src_ip])
    
    if len(unique_ports) >= scan_thresh:
        alerts.append(f"PORT SCAN detected from {src_ip} ({len(unique_ports)} ports in {window}s)")
        block_ip(src_ip)
        _port_access[src_ip] = []  # reset after blocking

    # --- SYN Flood Detection ---
    if flags and 'S' in flags and 'A' not in flags:
        _syn_counts[src_ip].append(now)
        _syn_counts[src_ip] = [t for t in _syn_counts[src_ip] if now - t <= window]
        
        if len(_syn_counts[src_ip]) >= syn_thresh:
            alerts.append(f"SYN FLOOD detected from {src_ip} ({len(_syn_counts[src_ip])} SYNs in {window}s)")
            block_ip(src_ip)
            _syn_counts[src_ip] = []

    return alerts

def get_stats():
    return {
        'tracked_ips': len(_port_access),
        'syn_tracked': len(_syn_counts)
    }
