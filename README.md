# 🛡️ PyGuard — Python Network Firewall & IDS

A real-time network firewall and intrusion detection system built with Python and Streamlit.

## Features
- 🔥 Live packet capture and filtering
- ⚙️ Rule engine — block/allow by IP, port, protocol
- 🚨 IDS — detects port scans and SYN flood attacks
- 🚫 Auto IP blocking on threat detection
- 📊 Live dashboard with traffic charts
- 🧪 Simulation mode for demo without admin rights

## Tech Stack
- Python 3.x
- Scapy (packet capture)
- Streamlit (dashboard GUI)
- Pandas (data handling)

## How to Run

### 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/pyguard.git
cd pyguard

### 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

### 3. Install dependencies
pip install -r requirements.txt

### 4. Run the app
streamlit run app.py

> For live capture mode, run VS Code as Administrator and install Npcap from https://npcap.com

## Pages
| Page | Description |
|---|---|
| Dashboard | Live stats and traffic charts |
| Live Feed | Real-time packet table |
| Rules Manager | Add/delete firewall rules, block IPs |
| Alerts | IDS threat detections |
| Logs | Full packet history |
