# SCADA Security Assignment - Read Me Or Fail

**Authors:** Defalt, orhunburakiyanc  
**Date:** 2025-12-23 (Updated)  
**Kernel:** Django 5.x on Python 3.x

## What is this garbage?

This is a SCADA simulation environment. It's not real SCADA, obviously, because real SCADA runs on ancient hardware and C code that nobody has touched since 1998. This is a Python/Django web app designed to demonstrate why security matters.

I built this with three distinct components because I hate monolithic messes:

1. **`vulnerable`**: This app is a disaster. It has 9 vulnerabilities (Auth Bypass, SQLi, IDOR, XXE, Deserialization RCE, File Upload/Overwrite, Race Condition, SSRF, Security Misconfiguration). It's written like a junior dev's first commit on a Friday afternoon.
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

* **SQL Injection:** `/vulnerable/dashboard/?connector=OR&is_locked_out=True`
  * *Why:* Dynamic query building.
  * *Visual:* If successful, the hidden **"NUCLEAR-CORE-CONTROLLER"** will appear in the list with a **Red Background**.

* **IDOR (Insecure Direct Object Reference):** `/vulnerable/report/?id=103`
  * *Why:* No authorization check on report access. Enumerate IDs 103-143 to access all diagnostic reports including admin secrets.
  * *Exploit:* `for i in {103..143}; do curl "http://localhost:8000/vulnerable/report/?id=$i" -o "report_$i.pdf"; done`

* **File Upload/Overwrite:** `/vulnerable/upload/`
  * *Why:* No filename sanitization, same filename overwrites previous file. Upload `diagnostic_script.txt` with malicious content.
  * *Impact:* Backdoor installation, production script replacement, no file versioning.

* **XXE (XML External Entity):** `/vulnerable/upload/`
  * *Why:* `resolve_entities=True` in the XML parser. Upload malicious XML to read local files like `/etc/passwd`.
  * *Example Output:* Full system user list including root, daemon, www-data accounts.

* **Deserialization RCE:** `/vulnerable/deserialize/`
  * *Why:* Accepts Base64 encoded `pickle` data without validation. RCE via `__reduce__()` method.
  * *Exploit:* Use `python3 create_pickle_payload.py` to generate payload, verify with `docker compose exec web cat /tmp/pwned.txt`

* **Race Condition:** `/vulnerable/report/`
  * *Why:* Uses static filename `/tmp/scada_report_temp.pdf` for all reports. Concurrent requests can leak data.

* **SSRF (Server-Side Request Forgery):** `/vulnerable/ssrf/`
  * *Why:* It blindly takes a URL and runs `urllib.request.urlopen()`. Try accessing `http://127.0.0.1:8000/admin/`.

* **Security Misconfiguration:** `/monitoring/` (accessible without admin check in vulnerable mode)
  * *Why:* OWASP A05:2021 - Missing authorization on security logs page. Normal users can view attack logs.
  * *Fix in Patched:* `/monitoring/patched/` requires admin authentication.

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


<img width="1570" height="961" alt="image" src="https://github.com/user-attachments/assets/89a9f980-592c-4dfc-98ba-3108330538d4" />
<img width="1576" height="957" alt="image" src="https://github.com/user-attachments/assets/e53e9598-43e5-4846-9d2e-1fd5c776cdaa" />
