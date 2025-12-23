# SCADA Security Assignment - Read Me Or Fail

**Author:** Defalt
**Date:** 2025-12-23  
**Kernel:** Django 5.x on Python 3.x

## What is this garbage?

This is a SCADA simulation environment. It's not real SCADA, obviously, because real SCADA runs on ancient hardware and C code that nobody has touched since 1998. This is a Python/Django web app designed to demonstrate why security matters.

I built this with three distinct components because I hate monolithic messes:

1. **`vulnerable`**: This app is a disaster. It has every hole in the book (SQLi, IDOR, XXE, SSRF). It's written like a junior dev's first commit on a Friday afternoon.
2. **`patched`**: This is how code *should* be written. Input sanitization, parameterized queries, CSRF protection. It actually works.
3. **`monitoring`**: A middleware layer that sits between the user and the server. It watches traffic. If it sees you trying to inject SQL, it logs you.

## The Architecture (Don't overcomplicate it)

The structure is simple. Keep it that way.

```
scada_assignment/
├── db.sqlite3          # The database. Don't delete it unless you want to re-run everything.
├── manage.py           # The commander.
├── core/               # Shared models (Devices, Logs). The backbone.
├── vulnerable/         # The playground for hackers.
├── patched/            # The playground for adults.
└── monitoring/         # The surveillance state.
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
# We need 'lxml' for XML parsing and 'reportlab' for PDFs. 'Faker' is for the dummy data.
pip install django faker lxml requests reportlab
```

### 2. Database Initialization

We need a database. We also need data because an empty database is useless for testing. I wrote a custom command `populate_db` to save you from typing 100 entries manually. You're welcome.

```bash
# create the tables
python manage.py makemigrations
python manage.py migrate

# fill it with junk data (100+ records)
python manage.py populate_db
```

### 3. Run the Thing

```bash
python manage.py runserver
```

If it says `System check identified no issues`, you are good. If it crashes, read the traceback. Python tells you exactly what is wrong.

## How to Break It (The Vulnerable App)

Go to these URLs to see bad code in action.

* **Auth Bypass:** `http://127.0.0.1:8000/vulnerable/login/?username=hacker&is_admin=True`
  * Why: Dictionary expansion in `request.GET`. Stupid.

* **SQL Injection:** `http://127.0.0.1:8000/vulnerable/dashboard/?connector=OR`
  * Why: Dynamic query building with user input.

* **XXE:** `http://127.0.0.1:8000/vulnerable/upload/`
  * Why: `resolve_entities=True` in the XML parser. Upload a payload and watch it read `/etc/passwd`.

* **SSRF:** `http://127.0.0.1:8000/vulnerable/ssrf/`
  * Why: Blind `requests.get()`.

## How to Verify It Works (The Patched App)

Go here to see the fixes.

* **Secure Login:** `http://127.0.0.1:8000/patched/login/`
  * Fix: Explicit field lookup.

* **Secure Dashboard:** `http://127.0.0.1:8000/patched/dashboard/`
  * Fix: Hardcoded filters.

* **Secure Upload:** `http://127.0.0.1:8000/patched/upload/`
  * Fix: UUID renaming, extension checks, `resolve_entities=False`.

## The Monitoring System

Check `http://127.0.0.1:8000/monitoring/`.

It uses Middleware (`monitoring/middleware.py`) to regex scan the raw request URL (`request.get_full_path()`). If you trigger an attack on the vulnerable app, it shows up here. If it doesn't show up, you didn't attack hard enough.

## Final Note

If you restart the computer, just run `source venv/bin/activate` and `python manage.py runserver` again. The database persists in the `db.sqlite3` file.

Now go finish your report.