from flask import Flask, render_template, request, send_file
import threading
import time
import nmap
import pickle
from scanner import scan_target

app = Flask(__name__)

# Load ML model
with open("port_risk_model.pkl", "rb") as f:
    model = pickle.load(f)

# Protocol mapping
protocol_map = {
    "tcp": 0,
    "udp": 1,
    "icmp": 2,
    "sctp": 3
}

# Reverse mapping for risk level
risk_mapping = {
    0: "Low",
    1: "Medium",
    2: "High"
}

scanner = nmap.PortScanner()
scan_result = []


def run_scan(target, scan_type):
    global scan_result
    scan_result = []  # Reset results

    if scan_type == "top":
        args = "-T4 -n --top-ports 50"
    else:
        args = "-T4 -n -p-"

    scanner.scan(target, arguments=args)

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            proto_num = protocol_map.get(proto.lower(), 0)  # default to TCP if unknown
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == "open":
                    try:
                        risk_level = model.predict([[port, proto_num]])[0]
                        risk = risk_mapping[risk_level]
                    except:
                        risk = "Unknown"
                else:
                    risk = "Closed"
                scan_result.append({
                    "host": host,
                    "protocol": proto,
                    "port": port,
                    "state": state,
                    "risk": risk
                })


@app.route("/", methods=["GET", "POST"])
def index():
    global scan_result
    if request.method == "POST":
        target = request.form["target"]
        scan_type = request.form["scan_type"]

        # Start scanning in a thread
        thread = threading.Thread(target=run_scan, args=(target, scan_type))
        thread.start()
        thread.join(timeout=30)  # optional: timeout

        return render_template("index.html", results=scan_result)

    return render_template("index.html", results=None)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
