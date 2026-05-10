import streamlit as st
import pandas as pd
import time
from core.firewall import (
    start_firewall, stop_firewall,
    packet_feed, alert_feed, stats,
    get_interfaces
)
from core.rules_engine import (
    load_rules, add_rule, delete_rule,
    block_ip, unblock_ip
)
from utils.logger import read_logs, clear_logs

# ----------------------------------------------------------------
# Page config
# ----------------------------------------------------------------
st.set_page_config(
    page_title="PyGuard Firewall",
    page_icon="🛡️",
    layout="wide"
)

# ----------------------------------------------------------------
# Sidebar — Controls
# ----------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/color/96/firewall.png", width=80)
st.sidebar.title("🛡️ PyGuard")
st.sidebar.markdown("---")

mode = st.sidebar.radio("Mode", ["🧪 Simulate", "🔴 Live Capture"])

interfaces = get_interfaces()
selected_iface = st.sidebar.selectbox("Network Interface", interfaces)

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("▶ Start", use_container_width=True, type="primary"):
        if mode == "🧪 Simulate":
            from simulate import start_simulation
            start_simulation()
        else:
            start_firewall(iface=selected_iface)
        st.success("Started!")
with col2:
    if st.button("⏹ Stop", use_container_width=True):
        if mode == "🧪 Simulate":
            from simulate import stop_simulation
            stop_simulation()
        else:
            stop_firewall()
        st.warning("Stopped.")

# Status indicator
status = "🟢 LIVE" if stats['running'] else "🔴 STOPPED"
st.sidebar.markdown(f"### Status: {status}")
st.sidebar.markdown("---")

# Navigation
page = st.sidebar.radio("Navigate", [
    "📊 Dashboard",
    "📋 Live Feed",
    "⚙️ Rules Manager",
    "🚨 Alerts",
    "📁 Logs"
])

# ----------------------------------------------------------------
# PAGE 1 — Dashboard
# ----------------------------------------------------------------
if page == "📊 Dashboard":
    st.title("📊 PyGuard Dashboard")

    # Stat cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets", stats['total'])
    c2.metric("✅ Allowed", stats['allowed'])
    c3.metric("🚫 Blocked", stats['blocked'])
    c4.metric("⚠️ Alerts", stats['alerts'])

    st.markdown("---")

    # Traffic chart from logs
    logs = read_logs()
    if logs:
        df = pd.DataFrame(logs)
        if 'action' in df.columns and 'protocol' in df.columns:
            col_a, col_b = st.columns(2)

            with col_a:
                st.subheader("Traffic by Action")
                action_counts = df['action'].value_counts().reset_index()
                action_counts.columns = ['Action', 'Count']
                st.bar_chart(action_counts.set_index('Action'))

            with col_b:
                st.subheader("Traffic by Protocol")
                proto_counts = df['protocol'].value_counts().reset_index()
                proto_counts.columns = ['Protocol', 'Count']
                st.bar_chart(proto_counts.set_index('Protocol'))

            st.subheader("Top Source IPs")
            top_ips = df['src_ip'].value_counts().head(10).reset_index()
            top_ips.columns = ['Source IP', 'Packet Count']
            st.dataframe(top_ips, use_container_width=True)
    else:
        st.info("No traffic data yet. Start the firewall to see charts.")

    # Auto-refresh
    time.sleep(2)
    st.rerun()

# ----------------------------------------------------------------
# PAGE 2 — Live Feed
# ----------------------------------------------------------------
elif page == "📋 Live Feed":
    st.title("📋 Live Packet Feed")

    if not stats['running']:
        st.warning("Firewall is not running. Click ▶ Start in the sidebar.")

    if packet_feed:
        df = pd.DataFrame(list(packet_feed))
        def color_action(val):
            color = '#1a9c3e' if val == 'ALLOW' else '#c0392b'
            return f'color: {color}; font-weight: bold'
        st.dataframe(
           df.style.map(color_action, subset=['action']),
            use_container_width=True,
            height=500
        )
    else:
        st.info("Waiting for packets...")

    time.sleep(1)
    st.rerun()

# ----------------------------------------------------------------
# PAGE 3 — Rules Manager
# ----------------------------------------------------------------
elif page == "⚙️ Rules Manager":
    st.title("⚙️ Rules Manager")

    data = load_rules()

    # Current rules table
    st.subheader("Current Rules")
    if data['rules']:
        rules_df = pd.DataFrame(data['rules'])
        st.dataframe(rules_df, use_container_width=True)

        del_id = st.number_input("Delete Rule by ID", min_value=1, step=1)
        if st.button("🗑️ Delete Rule", type="primary"):
            delete_rule(int(del_id))
            st.success(f"Rule {del_id} deleted!")
            st.rerun()
    else:
        st.info("No rules defined yet.")

    st.markdown("---")

    # Add new rule
    st.subheader("➕ Add New Rule")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        new_name = st.text_input("Rule Name")
    with col2:
        new_proto = st.selectbox("Protocol", ["TCP", "UDP"])
    with col3:
        new_port = st.number_input("Destination Port", min_value=1, max_value=65535, value=80)
    with col4:
        new_action = st.selectbox("Action", ["BLOCK", "ALLOW"])

    if st.button("✅ Add Rule"):
        if new_name:
            add_rule(new_name, new_proto, new_port, new_action)
            st.success(f"Rule '{new_name}' added!")
            st.rerun()
        else:
            st.error("Please enter a rule name.")

    st.markdown("---")

    # Blocked IPs
    st.subheader("🚫 Blocked IPs")
    blocked = data.get('blocked_ips', [])
    if blocked:
        for ip in blocked:
            col_ip, col_btn = st.columns([3, 1])
            col_ip.write(f"🔴 {ip}")
            if col_btn.button(f"Unblock", key=f"unblock_{ip}"):
                unblock_ip(ip)
                st.success(f"{ip} unblocked!")
                st.rerun()
    else:
        st.info("No IPs currently blocked.")

    manual_ip = st.text_input("Manually Block an IP")
    if st.button("🚫 Block IP"):
        if manual_ip:
            block_ip(manual_ip)
            st.success(f"{manual_ip} blocked!")
            st.rerun()

# ----------------------------------------------------------------
# PAGE 4 — Alerts
# ----------------------------------------------------------------
elif page == "🚨 Alerts":
    st.title("🚨 Threat Alerts")

    if alert_feed:
        df = pd.DataFrame(list(alert_feed))
        st.dataframe(df, use_container_width=True, height=500)
    else:
        st.success("No threats detected yet. All clear!")

    time.sleep(2)
    st.rerun()

# ----------------------------------------------------------------
# PAGE 5 — Logs
# ----------------------------------------------------------------
elif page == "📁 Logs":
    st.title("📁 Full Log History")

    logs = read_logs()
    if logs:
        df = pd.DataFrame(logs)
        st.dataframe(df, use_container_width=True, height=500)

        if st.button("🗑️ Clear All Logs", type="primary"):
            clear_logs()
            st.success("Logs cleared!")
            st.rerun()
    else:
        st.info("No logs yet.")
        