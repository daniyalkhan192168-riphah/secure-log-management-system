import subprocess
import json
import urllib.request
import socket
import re

API_URL = "http://192.168.1.20:8000/logs/add"
HOSTNAME = socket.gethostname()

def detect_event_type(message):
    msg = message.lower()

    if "failed password" in msg or "authentication failure" in msg:
        return "AUTH_FAILED"
    if "accepted password" in msg or "accepted publickey" in msg:
        return "AUTH_SUCCESS"
    if "sudo" in msg:
        return "SUDO_COMMAND"
    if "session opened" in msg:
        return "SESSION_OPENED"
    if "session closed" in msg:
        return "SESSION_CLOSED"
    if "ssh" in msg:
        return "SSH_EVENT"
    if "ufw" in msg:
        return "FIREWALL_EVENT"
    if "error" in msg or "failed" in msg:
        return "SYSTEM_ERROR"

    return "SYSTEM_EVENT"

def extract_ip(message):
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", message)
    return match.group(0) if match else "127.0.0.1"

def send_log(message):
    payload = {
        "source": f"Ubuntu-{HOSTNAME}",
        "event_type": detect_event_type(message),
        "username": "vboxuser",
        "ip_address": extract_ip(message),
        "message": message[:700]
    }

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        urllib.request.urlopen(req, timeout=5)
        print("[SENT]", payload["event_type"])
    except Exception as e:
        print("[ERROR]", e)

def main():
    print("Ubuntu Log Collector Agent Started")
    print("Sending logs to:", API_URL)
    print("Reading live Ubuntu logs from journalctl...")

    process = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        line = line.strip()
        if line:
            send_log(line)

if __name__ == "__main__":
    main()