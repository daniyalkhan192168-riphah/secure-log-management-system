import random
import requests
import time

API_URL = "http://127.0.0.1:8000/logs/add"

sources = [
    "Ubuntu-HR-Server",
    "Ubuntu-Finance-Server",
    "Ubuntu-Web-Server",
    "Ubuntu-Database-Server",
    "Firewall-Gateway",
    "VPN-Server",
    "Company-Web-App",
    "Windows-Admin-PC",
]

event_types = [
    "AUTH_FAILED",
    "AUTH_SUCCESS",
    "SUDO_COMMAND",
    "SESSION_OPENED",
    "SESSION_CLOSED",
    "FIREWALL_BLOCKED",
    "FIREWALL_ALLOWED",
    "APP_LOGIN_FAILED",
    "APP_LOGIN_SUCCESS",
    "SERVICE_RESTARTED",
    "SYSTEM_ERROR",
    "DATABASE_ACCESS",
]

users = [
    "admin",
    "root",
    "employee1",
    "employee2",
    "manager",
    "finance_user",
    "hr_user",
    "guest",
    "unknown",
]

messages = {
    "AUTH_FAILED": "Failed SSH login attempt detected",
    "AUTH_SUCCESS": "Successful SSH login recorded",
    "SUDO_COMMAND": "User executed privileged sudo command",
    "SESSION_OPENED": "User session opened",
    "SESSION_CLOSED": "User session closed",
    "FIREWALL_BLOCKED": "Firewall blocked suspicious inbound connection",
    "FIREWALL_ALLOWED": "Firewall allowed network traffic",
    "APP_LOGIN_FAILED": "Application login failed due to invalid password",
    "APP_LOGIN_SUCCESS": "Application login successful",
    "SERVICE_RESTARTED": "System service restarted successfully",
    "SYSTEM_ERROR": "System error event recorded",
    "DATABASE_ACCESS": "Database access event recorded",
}


def random_ip():
    return f"192.168.{random.randint(1, 50)}.{random.randint(2, 254)}"


def create_log(index):
    event_type = random.choice(event_types)
    source = random.choice(sources)
    username = random.choice(users)
    ip_address = random_ip()

    message = (
        f"{messages[event_type]} | "
        f"Record #{index} | "
        f"Source={source} | "
        f"User={username} | "
        f"IP={ip_address}"
    )
    

    return {
        "source": source,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
        "message": message,
    }


def main():
    total_logs = 1000
    success = 0
    failed = 0

    print(f"Generating {total_logs} organization-style logs...")
    print(f"Sending logs to: {API_URL}")

    for i in range(1, total_logs + 1):
        payload = create_log(i)

        try:
            response = requests.post(API_URL, json=payload, timeout=10)

            if response.status_code == 200:
                success += 1
                print(f"[{i}/{total_logs}] Sent: {payload['event_type']} from {payload['source']}")
            else:
                failed += 1
                print(f"[FAILED] {i}: {response.status_code} - {response.text}")

        except Exception as e:
            failed += 1
            print(f"[ERROR] {i}: {e}")

        time.sleep(0.01)

    print("\nDone.")
    print(f"Successful logs: {success}")
    print(f"Failed logs: {failed}")


if __name__ == "__main__":
    main()