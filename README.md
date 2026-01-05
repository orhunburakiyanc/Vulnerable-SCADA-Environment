# SCADA Security Assignment - Read Me Or Fail

**Authors:** Defalt, orhunburakiyanc  
**Date:** 2025-12-23 (Updated)  
**Kernel:** Django 5.x on Python 3.x

## What is this garbage?

This is a SCADA simulation environment. It's not real SCADA, obviously, because real SCADA runs on ancient hardware and C code that nobody has touched since 1998. This is a Python/Django web app designed to demonstrate why security matters.

I built this with three distinct components because I hate monolithic messes:

1. **`vulnerable`**: This app is a disaster. It has 11 vulnerabilities (Auth Bypass, Privilege Escalation, SQLi Scenarios 2a & 2b, IDOR [Vulnerability A], Deserialization RCE [Vulnerability B], File Upload/Overwrite [Vulnerabilities C & E], XXE [Vulnerability G], Race Condition [Vulnerability D], SSRF [Vulnerability F], Security Misconfiguration, Maintenance Interface CSRF). It's written like a junior dev's first commit on a Friday afternoon.
2. **`patched`**: This is how code *should* be written. Input sanitization, parameterized queries, CSRF protection, session management, and proper authorization checks. It actually works.
3. **`monitoring`**: A comprehensive security monitoring system. It detects 13 attack types, classifies severity (CRITICAL/HIGH/MEDIUM/LOW), tracks brute force attempts (5 failures/5min), and provides admin controls (block IP, revoke session, resolve incidents). Includes statistics dashboard and detailed logging.

## The Architecture (Don't overcomplicate it)

The structure is simple. Keep it that way.
```
scada_assignment/
├── db.sqlite3          # The database.
├── manage.py           # The commander.
├── core/               # Shared models (Devices, Reports). The backbone.
├── vulnerable/         # The playground for hackers.
├── patched/            # The playground for adults.
├── monitoring/         # The surveillance state (SOC).
├── docker-compose.yml  # The container orchestration.
├── Dockerfile          # The environment blueprint.
└── templates/          # HTML files (Now with a proper Navbar, you're welcome).
```

## Setup Instructions (The Old School Way)

If you are on a Mac (M4), you use `zsh`. If you are on Linux, you use `bash`. If you are on Windows, I can't help you.

### 1. Environment Setup

Don't install dependencies globally. It's messy and I hate it. Use a virtual environment.
```bash
# Get into the directory
cd scada_assignment

# Create the sandbox
python3 -m venv venv

# Activate it (You have to do this EVERY time you open a new terminal)
source venv/bin/activate

# Install the necessary libraries
pip install django faker lxml requests reportlab
```

### 2. Database Initialization

We need data. I updated the `populate_db` script. It creates specific targets for your scenarios (like a hidden **"NUCLEAR-CORE-CONTROLLER"**).
```bash
# Create the tables
python manage.py makemigrations
python manage.py migrate

# Fill it with scenario data
python manage.py populate_db
```

### 3. Run the Thing
```bash
python manage.py runserver
```

---

## Setup Instructions (The Docker Way - Recommended)

If you don't want to deal with python versions or dependencies, use Docker. It isolates everything.

### 1. Build and Run

Make sure you have Docker Desktop installed and running.
```bash
# Start the container (using the new V2 command with a space)
docker compose up --build
```

*Note: If `docker compose` doesn't work, try `docker-compose` (with a hyphen), but you really should update your Docker.*

### 2. Initialize Database Inside Docker

The container starts with an empty brain. You need to inject the schema and data. **Open a new terminal window** (keep the first one running) and execute:
```bash
# Apply migrations inside the 'web' container
docker compose exec web python manage.py migrate

# Populate the database with dummy data and hidden targets
docker compose exec web python manage.py populate_db
```

### 3. Access

Go to `http://localhost:8000`.

**Test Credentials:**
- Regular User: `user` / `user123`
- Admin: `admin` / `admin123`

**Container Commands:**
```bash
# View container file system (for deserialization RCE verification)
docker compose exec web cat /tmp/pwned.txt

# Access media directory (file upload tests)
docker compose exec web ls -la media/

# Check logs
docker compose logs -f web
```

*Note: I mapped the volumes (`.:/app`). This means if you change a file in your VS Code, it updates inside the container instantly. You don't need to rebuild for code changes.*

---

## UI Updates

I got tired of typing URLs manually, so I added a **Navbar** to the top of every page.

* **Vulnerable App:** Red/Blue theme.
* **Patched App:** Green theme (Secure).

## How to Break It (The Vulnerable App)

Go to these URLs (or just use the Navbar) to see bad code in action.

* **Auth Bypass:** `/vulnerable/login/?username=hacker&is_admin=True`
  * *Why:* Dictionary expansion in `request.GET`. It trusts whatever you put in the URL.
  * *Impact:* Passwordless admin access without any authentication.

* **Privilege Escalation:** `/vulnerable/dashboard/?is_admin=true` (after normal user login)
  * *Why:* URL parameters can overwrite session data.
  * *Impact:* Regular users can gain admin privileges via URL manipulation.

* **SQL Injection - Scenario 2a (Dashboard - Locked Device Revelation):** `/vulnerable/dashboard/?connector=OR&is_locked_out=True`
  * *Why:* Dynamic query building with user-controlled connector logic allows bypassing default filters.
  * *Impact:* Reveals locked-out devices including **"NUCLEAR-CORE-CONTROLLER"** with **Red Background** and 🔒 locked status.
  * *Admin Only:* Requires admin privileges (chain with Auth Bypass or Privilege Escalation).

* **SQL Injection - Scenario 2b (Maintenance - NUCLEAR Discovery):** `/vulnerable/maintenance/?connector=OR&name__icontains=NUCLEAR`
  * *Why:* Similar ORM filter bypass in maintenance interface allows revealing hidden NUCLEAR devices.
  * *Impact:* Bypasses need-to-know security policy, exposes critical infrastructure in maintenance mode.
  * *Admin Only:* Requires admin privileges.

* **IDOR (Insecure Direct Object Reference) [Vulnerability A - CWE-639]:** `/vulnerable/report/?id=103`
  * *Why:* No authorization check on report access. Enumerate IDs 103-153 to access all diagnostic reports including admin secrets.
  * *Exploit:* `for i in {103..153}; do curl "http://localhost:8000/vulnerable/report/?id=$i" -o "report_$i.pdf"; done`

* **File Upload/Overwrite [Vulnerabilities C & E - CWE-434]:** `/vulnerable/upload/`
  * *Why:* No filename sanitization or file type validation. Same filename overwrites previous file. Upload `diagnostic_script.txt` or dangerous file types (.php, .sh, .py).
  * *Impact:* Backdoor installation, production script replacement, no file versioning, unrestricted upload of dangerous file types.

* **XXE (XML External Entity) [Vulnerability G - CWE-611]:** `/vulnerable/upload/`
  * *Why:* `resolve_entities=True` in the XML parser. Upload malicious XML to read local files like `/etc/passwd`, `/etc/hostname`, or container files.
  * *Example Output:* Full system user list including root, daemon, www-data accounts. Successful file reads even when XML parsing appears to fail.

* **Deserialization RCE [Vulnerability B - CWE-502]:** `/vulnerable/deserialize/`
  * *Why:* Accepts Base64 encoded `pickle` data without validation. RCE via `__reduce__()` method.
  * *Exploit:* Upload malicious pickle file to execute arbitrary commands, verify with `docker compose exec web cat /tmp/pwned.txt`. Corrupted payloads can crash the server.

* **Race Condition [Vulnerability D - CWE-377 - Unsafe Temp Files]:** `/vulnerable/report/`
  * *Why:* Uses predictable static filename `/tmp/scada_report_temp.pdf` for all reports. Concurrent requests can overwrite each other's data, causing information disclosure.
  * *Impact:* User A's sensitive report data may leak to User B if requests are timed correctly.

* **SSRF (Server-Side Request Forgery) [Vulnerability F - CWE-918]:** `/vulnerable/ssrf/`
  * *Why:* No URL validation before `urllib.request.urlopen()`. Server makes arbitrary requests to attacker-controlled URLs.
  * *Exploit:* Access internal services (`http://127.0.0.1:8000/admin/`), scan internal network, exfiltrate data via webhook.site, access cloud metadata endpoints.

* **Security Misconfiguration - Unauthorized Monitoring Logs Access:** 
  * *Why:* OWASP A05:2021 - Security oversight where `/monitoring/` endpoint lacks authorization checks, allowing any user to access sensitive attack logs.
  * *Impact:* Information disclosure of attacker IPs, attack patterns, system vulnerabilities, blocked IPs, and security events. Enables reconnaissance for future attacks.
  * *Additional Issue:* DEBUG mode enabled shows detailed error pages with SECRET_KEY, database paths, environment variables on authentication failures.
  * *Fix in Patched:* Admin-only access to monitoring dashboard with proper authorization checks.

* **Maintenance Interface CSRF/Authorization:** `/vulnerable/maintenance/`
  * *Why:* OWASP A01:2021 + A05:2021 + A07:2021 - Missing server-side authorization check (only client-side redirect).
  * *Vulnerability:* Regular users see popup and redirect, but can bypass with JavaScript disabled or Burp Suite interception.
  * *Features:* Lockout/Tagout (LOTO) status tracking, technician assignment, maintenance logs viewer, statistics dashboard.
  * *Additional Flaws:*
    - @csrf_exempt on assign_technician and toggle_status (CSRF attacks possible)
    - No admin check on assign_technician (any logged user can modify if JS bypassed)
    - Information disclosure (maintenance data sent even to non-admin users)
  * *Exploit:* Disable JavaScript, intercept request with Burp, or create malicious HTML form for CSRF.
  * *Fix in Patched:* `/patched/maintenance/` requires admin authentication, CSRF protection enabled, input validation, LOTO compliance checks.

## How to Verify It Works (The Patched App)

Go here to see the fixes.

* **Secure Login:** `/patched/login/`
  * *Fix:* Explicit field lookup. Also, I fixed the **Logout** bug—it now actually flushes the session when you hit logout.

* **Secure Dashboard:** `/patched/dashboard/`
  * *Fix:* Hardcoded filters. You can't inject OR conditions anymore.

* **Secure SSRF:** `/patched/ssrf/`
  * *Fix:* **Allowlist**. You can only connect to `example.com` or `scada-update-server.com`. Everything else is blocked.

* **Secure Diagnostics:** `/patched/diagnostics/`
  * *Fix:* Switched from `pickle` to **JSON**. You can't execute code via JSON.

## The Monitoring System

Check `/monitoring/` for comprehensive security operations. Features:

* **Attack Detection:** 13 attack types (Auth Bypass, SQL Injection, XXE, File Upload, IDOR, Deserialization, SSRF, XSS, Path Traversal, Command Injection, Brute Force, Directory Scanning, Cookie Manipulation)
* **Severity Classification:** CRITICAL (RCE/Auth Bypass), HIGH (SQLi/XXE), MEDIUM (scanning), LOW (normal activity)
* **Brute Force Detection:** 5 failed login attempts within 5 minutes triggers CRITICAL alert
* **Admin Actions:** Block IP, Unblock IP, Revoke Session, Resolve Incident (requires admin authentication)
* **Statistics Dashboard:** Real-time counts for Critical Alerts, High Severity, Unresolved Incidents, Blocked IPs
* **Filters:** By severity, resolution status, attack type
* **Auto-blocking:** Configurable via `ENABLE_AUTO_BLOCKING` flag (disabled for demos)

**Security Misconfiguration Demo:** `/monitoring/` is accessible without admin check (vulnerability), while `/monitoring/patched/` requires authentication (fixed).

## Final Note

If you restart the computer:

* **Local:** `source venv/bin/activate` and `python manage.py runserver`
* **Docker:** `docker compose up`

The database persists in `db.sqlite3` in both cases.