#this was only used during the testing phases to replicate actual network traffic before using Scapy to monitor and capture realt time traffic
import json
import random
import hashlib
from datetime import datetime, timedelta

def generate_log_entry(device_id="device-001"):
    timestamp = datetime.utcnow().isoformat() + "Z"
    levels = ["INFO", "WARN", "ERROR", "ALERT"]
    level = random.choices(levels, weights=[70, 15, 10, 5])[0]
    message_templates = {
        "INFO": [
            "Connection established",
            "Heartbeat signal received",
            "Routine check successful"
        ],
        "WARN": [
            "High latency detected",
            "Disk space approaching limit",
            "Unusual configuration change"
        ],
        "ERROR": [
            "Failed login attempt",
            "Packet loss detected",
            "Timeout during data transfer"
        ],
        "ALERT": [
            "Port scan detected",
            "DDoS attack pattern identified",
            "Data exfiltration suspect"
        ]
    }
    message = random.choice(message_templates[level])
    source_ip = f"192.168.1.{random.randint(1,254)}"
    
    log = {
        "timestamp": timestamp,
        "device_id": device_id,
        "level": level,
        "message": message,
        "source_ip": source_ip
    }
    
    log_json = json.dumps(log, sort_keys=True)
    signature = hashlib.sha256(log_json.encode()).hexdigest()
    log["signature"] = signature
    
    return log

def generate_logs(count=1000):
    logs = []
    for _ in range(count):
        log = generate_log_entry()
        logs.append(log)
    return logs

if __name__ == "__main__":
    logs = generate_logs(100)
    with open("generated_network_logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print("Generated 100 signed network log entries in generated_network_logs.json")

