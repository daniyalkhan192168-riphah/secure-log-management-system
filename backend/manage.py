#!/usr/bin/env python3
"""
Setup and administration commands. Run from the backend folder.

  python manage.py init                  create backend/.env (admin password, token secret, first agent key)
  python manage.py add-agent NAME        create an API key for a new log agent
  python manage.py remove-agent NAME     revoke an agent's key
  python manage.py list-agents           show registered agents
  python manage.py set-password          change the dashboard admin password

Agent keys are shown ONCE. The .env file stores only their SHA-256 hashes.
Restart the backend after any change.
"""
import argparse
import getpass
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MIN_PASSWORD_LENGTH = 10


def _hash_password(password):
    # imported lazily so `init` works before any .env exists
    from services.auth import hash_password
    return hash_password(password)


def _new_agent_key():
    from services.auth import new_agent_key, hash_agent_key
    key = new_agent_key()
    return key, hash_agent_key(key)


# ------------------------------------------------------------ .env helpers
def read_env(path):
    values, order = {}, []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#") and "=" in s:
                    k, v = s.split("=", 1)
                    values[k.strip()] = v.strip()
                    order.append(k.strip())
    return values, order


def write_env(path, values):
    lines = [
        "# Secure Log backend secrets. NEVER commit this file. Created by manage.py.",
        "",
    ]
    groups = [
        ("# Dashboard login", ["SECURELOG_ADMIN_USERNAME", "SECURELOG_ADMIN_PASSWORD_HASH",
                               "SECURELOG_TOKEN_SECRET", "SECURELOG_TOKEN_TTL_MINUTES"]),
        ("# Log agents (name:sha256-of-key, comma separated)", ["SECURELOG_AGENT_KEYS"]),
        ("# Web settings", ["SECURELOG_CORS_ORIGINS", "SECURELOG_DEMO_MODE", "SECURELOG_ENABLE_DOCS"]),
    ]
    used = set()
    for title, keys in groups:
        lines.append(title)
        for k in keys:
            if k in values:
                lines.append(f"{k}={values[k]}")
                used.add(k)
        lines.append("")
    extra = [k for k in values if k not in used]
    if extra:
        lines.append("# Other settings")
        lines += [f"{k}={values[k]}" for k in extra]
        lines.append("")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def agents_from(values):
    agents = {}
    for item in values.get("SECURELOG_AGENT_KEYS", "").split(","):
        if ":" in item:
            name, digest = item.strip().split(":", 1)
            agents[name] = digest
    return agents


def agents_to(values, agents):
    values["SECURELOG_AGENT_KEYS"] = ",".join(f"{n}:{d}" for n, d in agents.items())


def ask_password(given=None):
    if given is not None:
        password = given
    else:
        password = getpass.getpass(f"New admin password (min {MIN_PASSWORD_LENGTH} chars): ")
        again = getpass.getpass("Repeat password: ")
        if password != again:
            sys.exit("Passwords do not match.")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    return password


def valid_agent_name(name):
    ok = name and len(name) <= 50 and all(c.isalnum() or c in "-_." for c in name)
    if not ok:
        sys.exit("Agent name may use letters, digits, '-', '_' and '.', up to 50 characters.")
    return name


def print_key(name, key):
    print()
    print("=" * 70)
    print(f" API key for agent '{name}'  (shown only once, copy it now):")
    print()
    print(f"   {key}")
    print()
    print(" Put it in agent.conf on that machine (api_key = ...).")
    print("=" * 70)


# ------------------------------------------------------------ commands
def cmd_init(args):
    if os.path.exists(args.env_file) and not args.force:
        sys.exit(f"{args.env_file} already exists. Use --force to replace it "
                 "(this logs everyone out and invalidates ALL agent keys).")
    username = args.username or input("Admin username [admin]: ").strip() or "admin"
    password = ask_password(args.password)
    print("Hashing password (PBKDF2, 600,000 rounds)...")
    key, digest = _new_agent_key()
    values = {
        "SECURELOG_ADMIN_USERNAME": username,
        "SECURELOG_ADMIN_PASSWORD_HASH": _hash_password(password),
        "SECURELOG_TOKEN_SECRET": secrets.token_hex(32),
        "SECURELOG_TOKEN_TTL_MINUTES": "480",
        "SECURELOG_AGENT_KEYS": f"{args.agent}:{digest}",
        "SECURELOG_CORS_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173",
        "SECURELOG_DEMO_MODE": "true" if args.demo else "false",
        "SECURELOG_ENABLE_DOCS": "true",
    }
    write_env(args.env_file, values)
    print(f"Created {args.env_file}")
    print(f"Dashboard login: {username} / (your password)   demo mode: {values['SECURELOG_DEMO_MODE']}")
    print_key(args.agent, key)


def cmd_add_agent(args):
    values, _ = read_env(args.env_file)
    if not values:
        sys.exit("No .env found. Run: python manage.py init")
    agents = agents_from(values)
    name = valid_agent_name(args.name)
    if name in agents and not args.force:
        sys.exit(f"Agent '{name}' exists. Use --force to replace its key (the old key stops working).")
    key, digest = _new_agent_key()
    agents[name] = digest
    agents_to(values, agents)
    write_env(args.env_file, values)
    print_key(name, key)
    print("Restart the backend to apply.")


def cmd_remove_agent(args):
    values, _ = read_env(args.env_file)
    agents = agents_from(values)
    if args.name not in agents:
        sys.exit(f"No agent named '{args.name}'.")
    del agents[args.name]
    agents_to(values, agents)
    write_env(args.env_file, values)
    print(f"Removed agent '{args.name}'. Restart the backend to apply.")


def cmd_list_agents(args):
    values, _ = read_env(args.env_file)
    agents = agents_from(values)
    if not agents:
        print("No agents registered.")
    for name, digest in agents.items():
        print(f"{name:30s} key hash {digest[:12]}...")


def cmd_set_password(args):
    values, _ = read_env(args.env_file)
    if not values:
        sys.exit("No .env found. Run: python manage.py init")
    values["SECURELOG_ADMIN_PASSWORD_HASH"] = _hash_password(ask_password(args.password))
    write_env(args.env_file, values)
    print("Password changed. Restart the backend to apply.")


def main():
    ap = argparse.ArgumentParser(description="Secure Log backend administration")
    ap.add_argument("--env-file", default=os.path.join(HERE, ".env"))
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create backend/.env")
    p.add_argument("--username")
    p.add_argument("--password", help="non-interactive (visible in shell history!)")
    p.add_argument("--agent", default="ubuntu-vm", help="name of the first agent")
    p.add_argument("--no-demo", dest="demo", action="store_false",
                   help="disable the demo attack buttons")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add-agent")
    p.add_argument("name")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_add_agent)

    p = sub.add_parser("remove-agent")
    p.add_argument("name")
    p.set_defaults(func=cmd_remove_agent)

    p = sub.add_parser("list-agents")
    p.set_defaults(func=cmd_list_agents)

    p = sub.add_parser("set-password")
    p.add_argument("--password", help="non-interactive (visible in shell history!)")
    p.set_defaults(func=cmd_set_password)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()