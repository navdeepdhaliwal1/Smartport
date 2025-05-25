# 🔌 SmartPort - Intelligent Port Scanner with Vulnerability Detection

SmartPort is an AI-enhanced port scanning and service enumeration tool designed for cybersecurity professionals, penetration testers, and network administrators. It combines traditional port scanning with intelligent fingerprinting and basic vulnerability detection, all wrapped in a user-friendly web interface.

---

## 🚀 Features

- ⚡ Fast and multi-threaded port scanning (TCP/UDP)
- 🧠 Intelligent service fingerprinting using banners and custom rules
- 🔍 Basic vulnerability detection (misconfigurations, common CVEs)
- 🌐 Flask-based web dashboard to view scan results in real time
- 🛠️ Modular architecture – easy to extend with your own plugins
- 📄 Export results to JSON, CSV, or HTML formats

---

## 📸 Demo Screenshot

> *(Add a screenshot of the web dashboard here)*  
`![SmartPort Dashboard](screenshots/dashboard.png)`
![Screenshot 2025-05-25 102941](https://github.com/user-attachments/assets/7d6ad818-dbea-4da0-b1f5-6af1e86b5a20)
> ![Screenshot 2025-05-25 102953](https://github.com/user-attachments/assets/bf48040e-25ea-44d2-97cd-0da25d4f0322)


---

## 🛠️ Tech Stack

- **Python** – Core engine for scanning and logic
- **Flask** – Web-based dashboard
- **Bash** – Optional scripts for automation
- **Nmap (optional)** – Backend scanner integration
- **SQLite / JSON** – Data storage and export

---

## 📦 Installation

### Requirements

- Python 3.7+
- pip
- Git
- (Optional) Nmap

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/smartport.git
cd smartport

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
🧪 Usage
Open your browser and go to http://127.0.0.1:5000

Enter the target IP/domain and select scan options.

Click "Start Scan" and view live results.

🔒 Disclaimer
This tool is intended for educational and authorized penetration testing purposes only. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal.

