import subprocess
import json
import urllib.request
import socket
import re

# --- CONFIGURATION ---
# 1. Change this to your Backend IP. Use "http://127.0.0.1:8000/logs/add" if running on the same PC.
API_URL = "http://192.168.1.38:8000/logs/add"

# 2. This MUST match the API_KEY you set in your backend's main.py
API_KEY = "secure-log-secret-2026" 

HOSTNAME = socket.gethostname( )

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
    if "ssh" in msg:
        return "SSH_EVENT"
    return "SYSTEM_EVENT"

def extract_ip(message):
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", message)
    return match.group(0) if match else "127.0.0.1"

def send_log(message):
    payload = {
        "source": f"Ubuntu-{HOSTNAME}",
        "event_type": detect_event_type(message),
        "username": "vboxuser", # You can change this to your Ubuntu username
        "ip_address": extract_ip(message),
        "message": message[:700]
    }

    data = json.dumps(payload).encode("utf-8")

    # This is the important part: we add the 'X-API-KEY' to the headers
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": API_KEY 
        },
        method="POST"
    )

    try:
        urllib.request.urlopen(req, timeout=5)
        print(f"[SUCCESS] Sent {payload['event_type']} log to backend.")
    except Exception as e:
        print(f"[ERROR] Could not send log. Is the backend running? Error: {e}")

def main():
    print("--- Ubuntu Log Collector Agent Started ---")
    print(f"Sending logs to: {API_URL}")
    print("Watching live system logs (journalctl)...")

    # This command reads the live logs from your Ubuntu system
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
