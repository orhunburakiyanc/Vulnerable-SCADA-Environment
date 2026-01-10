# Vulnerable SCADA Environment - Security Lab

**CS437 Cybersecurity Project**  
**Authors:** Orhun Burak Kıyanç, Mehmet Altunören, Ege Tan  
**Technology Stack:** Django 5.0.13 (CVE-2025-64459 vulnerable), Python 3.12, Docker  
**Repository:** [GitHub](https://github.com/orhunburakiyanc/Vulnerable-SCADA-Environment)

## Overview

A simulated SCADA (Supervisory Control and Data Acquisition) environment demonstrating **9 critical web application vulnerabilities** commonly found in industrial control systems.

### Three-Layer Architecture

1. **`vulnerable/`** - Intentionally insecure implementations with 9 exploitable vulnerabilities
2. **`patched/`** - Secure implementations with proper mitigations (CSRF protection, input validation, authorization)
3. **`monitoring/`** - Real-time attack detection system with severity classification and admin controls

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
- **Regular User (Field Technician)**: `user` / `user123`
  - Role: Upload diagnostics, view reports, check remote nodes
  - Cannot access: Dashboard (device list), Maintenance Interface
- **Admin (System Administrator)**: `admin` / `admin123`
  - Role: Full system access including device management
  - Can access: All features including dashboard and maintenance

**Role-Based Access Control (Real-World Scenario):**
In industrial SCADA systems, field technicians need to upload diagnostic logs and check remote node status, but should NOT have visibility into all critical infrastructure devices or ability to perform maintenance operations. Only system administrators should manage devices, especially critical systems like NUCLEAR-CORE-CONTROLLER.

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

## 9 Implemented Vulnerabilities

### 1. Authentication Bypass (CVE-2025-64459)
**Exploit:** `/vulnerable/login/?connector=OR&is_superuser=true`  
**Impact:** Passwordless admin access via Django Q() connector parameter manipulation

### 2. IDOR - Insecure Direct Object Reference
**Exploit:** `/vulnerable/report/?id=103` (enumerate 103-153)  
**Impact:** Access any user's diagnostic reports without authorization

### 3. Insecure Deserialization (RCE)
**Exploit:** `/vulnerable/deserialize/` - Upload malicious pickle payload  
**Impact:** Remote code execution via `__reduce__()` method  
**Verify:** `docker compose exec web cat /tmp/pwned.txt`

### 4. File Overwrite
**Exploit:** `/vulnerable/upload/` - Upload file with existing name  
**Impact:** Overwrite production files without versioning

### 5. Unrestricted File Upload
**Exploit:** Upload `.php`, `.exe`, `.sh`, `.py` files  
**Impact:** Web shell installation, backdoor deployment

### 6. XXE Injection
**Exploit:** Upload XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`  
**Impact:** Read local files (`/etc/passwd`, `/etc/hostname`)

### 7. SSRF - Server-Side Request Forgery
**Exploit:** `/vulnerable/ssrf/?url=http://127.0.0.1:8000/admin/`  
**Impact:** Access internal services, cloud metadata (169.254.169.254)

### 8. Privilege Escalation + SQL Injection
**Exploit:** `/vulnerable/dashboard/?connector=OR&name__icontains=NUCLEAR`
**Exploit:** `/vulnerable/dashboard/?is_admin=true`
**Impact:** Reveal hidden NUCLEAR-CORE-CONTROLLER device via ORM filter bypass

### 9. Unsafe Temporary Files (Race Condition)
**Exploit:** Parallel requests to `/vulnerable/report/?id=1` and `?id=103`  
**Impact:** Information disclosure via shared temp file `/tmp/scada_report_temp.pdf`

## Patched Implementations

Secure versions at `/patched/` endpoints:

- **Login:** POST-only, Django `authenticate()`, no URL parameters
- **Dashboard:** Hardcoded filters, no dynamic Q() objects
- **Upload:** UUID filenames, extension whitelist, XXE disabled
- **Deserialization:** JSON instead of pickle
- **SSRF:** Domain allowlist only
- **Reports:** No temp files, ownership verification
- **CSRF Protection:** All state-changing operations

## Monitoring System

Real-time attack detection middleware: `/monitoring/`

**Features:**
- **13 Attack Patterns:** Auth Bypass, SQL Injection, XXE, File Upload, IDOR, Deserialization, SSRF, Path Traversal, Brute Force, Directory Scanning, Cookie Manipulation
- **Severity Levels:** CRITICAL (RCE/Auth Bypass), HIGH (SQLi/XXE), MEDIUM (scanning), LOW
- **Brute Force Detection:** 7+ attempts/min (HIGH), 10+ attempts/min (CRITICAL)
- **Admin Actions:** Block IP, Revoke Session, Resolve Incident
- **Auto-blocking:** Configurable via `ENABLE_AUTO_BLOCKING` (disabled for demos)

**Demo:** `/monitoring/` lacks auth (misconfiguration), `/monitoring/patched/` requires admin

## Final Note

If you restart the computer:

* **Local:** `source venv/bin/activate` and `python manage.py runserver`
* **Docker:** `docker compose up`

The database persists in `db.sqlite3` in both cases.