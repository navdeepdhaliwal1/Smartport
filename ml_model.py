import pickle
from sklearn.tree import DecisionTreeClassifier

# Feature encoding: [port_number, protocol]
# Protocol: 0 = TCP, 1 = UDP, 2 = ICMP, 3 = SCTP

X = [
    [22, 0],    # SSH - TCP
    [80, 0],    # HTTP - TCP
    [443, 0],   # HTTPS - TCP
    [21, 0],    # FTP - TCP
    [3389, 0],  # RDP - TCP
    [53, 1],    # DNS - UDP
    [69, 1],    # TFTP - UDP
    [161, 1],   # SNMP - UDP
    [7, 2],     # Echo - ICMP
    [500, 3],   # ISAKMP - SCTP
    [5060, 3],  # SIP - SCTP
    [23, 0],    # Telnet - TCP
    [445, 0],   # SMB - TCP
    [3306, 0],  # MySQL - TCP
    [5432, 0],  # PostgreSQL - TCP
    [25, 0],    # SMTP - TCP
    [143, 0],   # IMAP - TCP
    [110, 0],   # POP3 - TCP
    [514, 0],   # Syslog - TCP
    [514, 1],   # Syslog - UDP
    [123, 1],   # NTP - UDP
    [179, 0],   # BGP - TCP
    [67, 1],    # DHCP - UDP
]

# Risk labels: 0 = Low, 1 = Medium, 2 = High
y = [
    1, 0, 0, 2, 2, 1, 2, 1,
    1, 1, 2, 2, 2, 0, 0, 2,
    1, 2, 0, 0, 1, 1, 1
]

# Train and save the model
model = DecisionTreeClassifier()
model.fit(X, y)

with open("port_risk_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained and saved as port_risk_model.pkl")
