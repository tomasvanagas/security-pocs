# Security PoCs

Proof-of-concept exploits for patched vulnerabilities in open-source software. Each directory contains a self-contained PoC with a writeup, exploit script, and a Docker Compose environment for safe reproduction.

All vulnerabilities listed here have been **responsibly disclosed** and are **patched** in latest versions.

<br/>

## Exploits

| Target | Vulnerability | Severity | Affected versions | Directory |
|--------|--------------|----------|-------------------|-----------|
| [DbGate](https://github.com/dbgate/dbgate) | Unauthenticated credential extraction (auth bypass + arbitrary file read) | Critical | 5.4.0–6.1.4 | [`DBGate--CredDiscl--5.4.0-6.1.4`](DBGate--CredDiscl--5.4.0-6.1.4/) |

<br/>

## Disclaimer

These exploits are provided for **educational and authorized security testing purposes only**. Only use them against systems you own or have explicit permission to test. The author is not responsible for any misuse.
