# SCADA Security Assignment - Read Me Or Fail

**Authors:** Defalt, orhunburakiyanc
**Date:** 2025-12-23 (Updated)
**Kernel:** Django 5.x on Python 3.x

## What is this garbage?

This is a SCADA simulation environment. It's not real SCADA, obviously, because real SCADA runs on ancient hardware and C code that nobody has touched since 1998. This is a Python/Django web app designed to demonstrate why security matters.

I built this with three distinct components because I hate monolithic messes:

1. **`vulnerable`**: This app is a disaster. It has every hole in the book (SQLi, IDOR, XXE, Deserialization, and now **SSRF**). It's written like a junior dev's first commit on a Friday afternoon.
2. **`patched`**: This is how code *should* be written. Input sanitization, parameterized queries, CSRF protection, and session management. It actually works.
3. **`monitoring`**: A middleware layer that sits between the user and the server. It watches traffic. If it sees you trying to inject SQL, it logs you. I also fixed the regex so it stops flagging normal page navigation as an attack.

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
└── templates/          # HTML files (Now with a proper Navbar, you're welcome).

```

## Setup Instructions

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

# Install the necessary libraries. 
pip install django faker lxml requests reportlab

```

### 2. Database Initialization (CRITICAL)

We need data. I updated the `populate_db` script. It doesn't just create random junk anymore; it creates specific targets for your scenarios (like a hidden **"NUCLEAR-CORE-CONTROLLER"** and an Admin report).

```bash
# Create the tables (including the missing DiagnosticResult table)
python manage.py makemigrations
python manage.py migrate

# Fill it with scenario data
python manage.py populate_db

```

### 3. Run the Thing

```bash
python manage.py runserver

```

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


* **SSRF (New):** `/vulnerable/ssrf/`
* *Why:* It blindly takes a URL and runs `urllib.request.urlopen()`. Try accessing `http://127.0.0.1:8000/admin/`.


* **XXE:** `/vulnerable/upload/`
* *Why:* `resolve_entities=True` in the XML parser. Upload a malicious XML to read local files.


* **Deserialization:** `/vulnerable/deserialize/`
* *Why:* It accepts Base64 encoded `pickle` data. RCE waiting to happen.



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

Check `/monitoring/`.

It uses Middleware to regex scan the raw request.

* **Update:** I fixed the logic where it was flagging the internal pipe `|` character as an attack. Now it logs *actual* attacks (SQLi, XSS, Command Injection) without spamming the logs for normal navigation.

## Final Note

If you restart the computer, just run `source venv/bin/activate` and `python manage.py runserver` again. The database persists in `db.sqlite3`.

Now go finish your report.