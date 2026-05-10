import threading
import time
from collections import deque
from datetime import datetime

# We import scapy carefully to suppress its startup warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, IP, TCP, UDP, conf

from core.rules_engine import check_packet, load_rules
from core.state_tracker import update_state, cleanup_old
from core.detector import inspect
from utils.logger import log_packet, log_alert

# ----------------------------------------------------------------
# Shared state — app.py reads these to display live data
# ----------------------------------------------------------------
packet_feed = deque(maxlen=100)   # last 100 packets for live table
alert_feed  = deque(maxlen=50)    # last 50 alerts
stats = {
    'total': 0,
    'allowed': 0,
    'blocked': 0,
    'alerts': 0,
    'running': False
}

_stop_event = threading.Event()
_thread = None

# ----------------------------------------------------------------
# Core packet handler — called for every captured packet
# ----------------------------------------------------------------
def _handle_packet(pkt):
    if not pkt.haslayer(IP):
        return  # ignore non-IP packets

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    protocol = 'OTHER'
    dst_port = 0
    flags    = ''

    if pkt.haslayer(TCP):
        protocol = 'TCP'
        dst_port = pkt[TCP].dport
        flags    = str(pkt[TCP].flags)
        update_state(src_ip, dst_ip, dst_port, flags)

    elif pkt.haslayer(UDP):
        protocol = 'UDP'
        dst_port = pkt[UDP].dport

    # Load current settings for detector thresholds
    try:
        settings = load_rules().get('settings', {})
    except:
        settings = {}

    # Run IDS threat detection
    alerts = inspect(src_ip, dst_port, flags, settings)
    for alert_msg in alerts:
        entry = log_alert(src_ip, alert_msg)
        alert_feed.appendleft(entry)
        stats['alerts'] += 1

    # Check firewall rules
    action, reason = check_packet(src_ip, dst_ip, protocol, dst_port)

    # Log and store the packet
    entry = log_packet(src_ip, dst_ip, protocol, dst_port, action, reason)
    packet_feed.appendleft(entry)

    # Update counters
    stats['total'] += 1
    if action == 'ALLOW':
        stats['allowed'] += 1
    else:
        stats['blocked'] += 1

# ----------------------------------------------------------------
# Cleanup thread — removes stale TCP connections every 60s
# ----------------------------------------------------------------
def _cleanup_loop():
    while not _stop_event.is_set():
        cleanup_old(timeout=120)
        time.sleep(60)

# ----------------------------------------------------------------
# Public controls — called from app.py
# ----------------------------------------------------------------
def start_firewall(iface=None):
    global _thread
    if stats['running']:
        return  # already running

    _stop_event.clear()
    stats['running'] = True

    # Start cleanup thread
    cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
    cleanup_thread.start()

    # Start packet sniffing in background thread
    def sniff_loop():
        sniff(
            iface=iface,
            prn=_handle_packet,
            store=False,
            stop_filter=lambda p: _stop_event.is_set()
        )
        stats['running'] = False

    _thread = threading.Thread(target=sniff_loop, daemon=True)
    _thread.start()

def stop_firewall():
    _stop_event.set()
    stats['running'] = False

def get_interfaces():
    """Return list of available network interfaces."""
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except:
        return ['eth0', 'Wi-Fi', 'lo']
    