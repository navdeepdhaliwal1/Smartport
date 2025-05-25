import json
import csv
import nmap
from tqdm import tqdm
from sklearn.tree import DecisionTreeClassifier
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Dummy ML training data (you can improve this later)
X_train = [
    [22, 0], [80, 0], [443, 0], [3389, 0], [8080, 0],
    [21, 0], [23, 0], [445, 0], [53, 0], [25, 0]
]
y_train = [1, 1, 0, 2, 1, 2, 2, 2, 0, 1]  # 0 = Low, 1 = Medium, 2 = High

# Train simple ML model
model = DecisionTreeClassifier()
model.fit(X_train, y_train)

# Risk label mapping
risk_mapping = {0: "Low", 1: "Medium", 2: "High"}


def scan_target(target, scan_type):
    scanner = nmap.PortScanner()
    report = []

    # Select scan type
    if scan_type == "1":
        print("\n[+] Scanning Top 100 Ports (Fast Scan)")
        print("[DEBUG] Starting scan...")
        scanner.scan(target, arguments='-T4 -n --top-ports 50')
        print("[DEBUG] Scan complete.")
    elif scan_type == "2":
        print("\n[+] Scanning All Ports (Full Scan - Slower)")
        scanner.scan(target, arguments='-T4 -n  -p-')
    else:
        print("[-] Invalid option. Scanning Top 50 Ports by default.")
        scanner.scan(target, arguments='-T4 -n  --top-ports 100')

    # Process scan results
    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            proto_num = 0 if proto.lower() == "tcp" else 1
            ports = scanner[host][proto].keys()

            # Progress bar for ports
            for port in tqdm(ports, desc=f"Scanning {proto.upper()} ports", unit="port"):
                state = scanner[host][proto][port]['state']
                entry = {
                    "host": host,
                    "protocol": proto,
                    "port": port,
                    "state": state,
                }

                if state == "open":
                    risk = model.predict([[port, proto_num]])[0]
                    risk_text = risk_mapping[risk]
                    entry["risk"] = risk_text

                    # Color-coded output
                    color = Fore.GREEN if risk == 0 else Fore.YELLOW if risk == 1 else Fore.RED
                    print(f"Port: {port} | State: {state} | Risk Level: {color}{risk_text}{Style.RESET_ALL}")
                else:
                    print(f"Port: {port} | State: {state}")

                report.append(entry)


    # Ask to save the report
    save_choice = input("\nDo you want to save the scan report? (Y/N): ").strip().lower()
    if save_choice == 'y':
        format_choice = input("Choose format - 1. TXT, 2. JSON, 3. CSV: ").strip()

        if format_choice == "1":
            with open("scan_report.txt", "w") as f:
                for entry in report:
                    line = f"Host: {entry['host']} | Protocol: {entry['protocol']} | Port: {entry['port']} | State: {entry['state']}"
                    if "risk" in entry:
                        line += f" | Risk: {entry['risk']}"
                    f.write(line + "\n")
            print("[+] Report saved as scan_report.txt")

        elif format_choice == "2":
            with open("scan_report.json", "w") as f:
                json.dump(report, f, indent=4)
            print("[+] Report saved as scan_report.json")

        elif format_choice == "3":
            with open("scan_report.csv", "w", newline='') as f:
                fieldnames = ["host", "protocol", "port", "state", "risk"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in report:
                    writer.writerow(entry)
            print("[+] Report saved as scan_report.csv")

        else:
            print("[-] Invalid format selected. Report not saved.")
    else:
        print("[*] Scan report not saved.")



#  ADD THIS IMPORTANT PART BELOW
if __name__ == "__main__":
    print("Welcome to AI Vulnerability Scanner!")
    target_ip = input("Enter the target URL or IP address or range (e.g., 192.168.1.1 or 192.168.1.1-10): ")
    print("\nChoose Scan Type:")
    print("1. Top 100 Ports (Fast)")
    print("2. Full Scan (All Ports)")
    scan_type = input("Enter option (1/2): ")

    scan_target(target_ip, scan_type)
