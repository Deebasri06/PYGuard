import time
import random
import threading
from datetime import datetime
from core.firewall import packet_feed, alert_feed, stats
from core.rules_engine import check_packet, load_rules
from core.detector import inspect
from utils.logger import log_packet, log_alert

# Realistic sample IPs and ports
SAMPLE_IPS = [
    "192.168.1.10", "192.168.1.25", "10.0.0.5",
    "172.16.0.3", "45.33.32.156", "8.8.8.8",
    "203.0.113.42", "198.51.100.7", "185.220.101.5"
]

SAMPLE_PORTS = [
    (80, "TCP"), (443, "TCP"), (22, "TCP"),
    (23, "TCP"), (3389, "TCP"), (53, "UDP"),
    (21, "TCP"), (8080, "TCP"), (3306, "TCP")
]

ATTACKER_IP = "185.220.101.5"   # will trigger port scan alert
DST_IP      = "192.168.1.1"

_stop_event = threading.Event()

def _simulate_loop():
    tick = 0
    while not _stop_event.is_set():
        tick += 1

        # Every 30 ticks — simulate a port scan from attacker IP
        if tick % 30 == 0:
            settings = load_rules().get('settings', {})
            for port in random.sample(range(1, 9999), 16):
                alerts = inspect(ATTACKER_IP, port, 'S', settings)
                for alert_msg in alerts:
                    entry = log_alert(ATTACKER_IP, alert_msg)
                    alert_feed.appendleft(entry)
                    stats['alerts'] += 1

        # Normal random packet
        src_ip = random.choice(SAMPLE_IPS)
        dst_port, protocol = random.choice(SAMPLE_PORTS)
        flags = 'S' if protocol == 'TCP' else ''

        try:
            settings = load_rules().get('settings', {})
            alerts = inspect(src_ip, dst_port, flags, settings)
            for alert_msg in alerts:
                entry = log_alert(src_ip, alert_msg)
                alert_feed.appendleft(entry)
                stats['alerts'] += 1

            action, reason = check_packet(src_ip, DST_IP, protocol, dst_port)
            entry = log_packet(src_ip, DST_IP, protocol, dst_port, action, reason)
            packet_feed.appendleft(entry)

            stats['total'] += 1
            if action == 'ALLOW':
                stats['allowed'] += 1
            else:
                stats['blocked'] += 1
        except Exception as e:
            pass

        time.sleep(0.5)   # one packet every 0.5 seconds

def start_simulation():
    if stats['running']:
        return
    _stop_event.clear()
    stats['running'] = True
    t = threading.Thread(target=_simulate_loop, daemon=True)
    t.start()

def stop_simulation():
    _stop_event.set()
    stats['running'] = False
    