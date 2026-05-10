import json
import os

RULES_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'rules.json')

def load_rules():
    with open(RULES_PATH, 'r') as f:
        return json.load(f)

def save_rules(data):
    with open(RULES_PATH, 'w') as f:
        json.dump(data, f, indent=2)

def check_packet(src_ip, dst_ip, protocol, dst_port):
    """
    Returns 'BLOCK' or 'ALLOW' based on rules.
    Blocked IPs are checked first, then port/protocol rules.
    Default action is ALLOW if no rule matches.
    """
    data = load_rules()

    # Check if source IP is in blocked list
    if src_ip in data.get('blocked_ips', []):
        return 'BLOCK', 'IP is in blocklist'

    # Check rules in order
    for rule in data['rules']:
        if not rule.get('enabled', True):
            continue
        proto_match = rule.get('protocol', '').upper() == protocol.upper()
        port_match = rule.get('dst_port') == dst_port
        ip_match = True
        if rule.get('src_ip'):
            ip_match = rule['src_ip'] == src_ip
        if proto_match and port_match and ip_match:
            return rule['action'], rule['name']

    return 'ALLOW', 'Default allow'

def add_rule(name, protocol, dst_port, action):
    data = load_rules()
    new_id = max((r['id'] for r in data['rules']), default=0) + 1
    data['rules'].append({
        'id': new_id,
        'name': name,
        'protocol': protocol.upper(),
        'dst_port': int(dst_port),
        'action': action.upper(),
        'enabled': True
    })
    save_rules(data)

def delete_rule(rule_id):
    data = load_rules()
    data['rules'] = [r for r in data['rules'] if r['id'] != rule_id]
    save_rules(data)

def block_ip(ip):
    data = load_rules()
    if ip not in data['blocked_ips']:
        data['blocked_ips'].append(ip)
        save_rules(data)

def unblock_ip(ip):
    data = load_rules()
    data['blocked_ips'] = [x for x in data['blocked_ips'] if x != ip]
    save_rules(data)
    