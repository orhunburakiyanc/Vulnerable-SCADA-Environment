from .models import AttackLog, BlockedIP, FailedLoginAttempt
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import re

# =============================================================================
# SECURITY MONITORING MIDDLEWARE - CS437 SCADA Security Lab
# =============================================================================
# This middleware intercepts ALL HTTP requests and detects security attacks
# in real-time. It monitors both vulnerable and patched endpoints.
#
#  
# "This is our SecurityMonitorMiddleware. It acts as a security layer that
# intercepts every HTTP request before it reaches the application. Let me
# show you how it detects each type of attack."
# =============================================================================

class SecurityMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.failed_404_attempts = {}  # IP -> [timestamps] for directory scanning
        self.suspicious_sessions = {}  # Session -> metadata

    def __call__(self, request):
        ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')
        
        # =====================================================================
        # IP BLOCKING CHECK
        # =====================================================================
        # "First, we check if this IP is already blocked.
        # If blocked, we immediately return 403 Forbidden."
        # =====================================================================
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden(
                "<h1>403 Forbidden</h1>"
                "<p>Your IP address has been blocked due to suspicious activity.</p>"
                "<p>Contact the administrator if you believe this is an error.</p>"
            )
        
        # Capture the full URL and POST body for analysis
        full_path = request.get_full_path()
        endpoint = request.path
        
        try:
            body_content = request.body.decode('utf-8', errors='ignore')
        except:
            body_content = ""

        search_space = f"{full_path} RAW_BODY: {body_content}"

        # Initialize attack detection variables
        attack_detected = None
        severity = 'MEDIUM'
        recommended_action = 'Review and investigate this attack'
        reverse_action = 'No action to reverse'
        
        # =====================================================================
        # VULNERABILITY DETECTION #1: BRUTE FORCE ATTACK
        # Location: check_brute_force() function (Line ~175)
        # =====================================================================
        # : "The first check is for Brute Force attacks. We track
        # login attempts per IP. If we see 5 or more attempts in 5 minutes,
        # we flag it as CRITICAL. 3-4 attempts is flagged as HIGH."
        # 
        # Detection Logic:
        # - Monitors /login/ endpoint
        # - Counts FailedLoginAttempt records per IP in last 5 minutes
        # - 5+ attempts = CRITICAL, 3-4 attempts = HIGH
        # =====================================================================
        brute_force_detected, bf_severity, bf_action = self.check_brute_force(ip_address, endpoint, request)
        if brute_force_detected:
            attack_detected = 'Brute Force Attack'
            severity = bf_severity
            recommended_action = bf_action
            reverse_action = f'Unblock IP {ip_address} and clear failed login attempts'
        
        # =====================================================================
        # VULNERABILITY DETECTION #2: AUTHENTICATION BYPASS (CVE-2025-64459)
        # Endpoint: /login/
        # =====================================================================
        # : "Next, we check for Authentication Bypass on the login
        # endpoint. We use regex to detect 'is_admin=true' or 'superuser=' in
        # the URL parameters. This catches dictionary expansion attacks."
        #
        # Detection Pattern: is_admin=true, is_admin=1, superuser=
        # Severity: CRITICAL
        # =====================================================================
        elif '/login/' in endpoint:
            if re.search(r"(?i)(is_admin=true|is_admin=1|superuser=)", search_space):
                attack_detected = 'Authentication Bypass (CVE-2025-64459)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE ACTION: Block IP, revoke all sessions from this IP, review authentication logs'
                reverse_action = f'Unblock IP {ip_address} if false positive'
        
        # =====================================================================
        # VULNERABILITY DETECTION #3 & #4: PRIVILEGE ESCALATION + SQL INJECTION
        # Endpoint: /dashboard/
        # =====================================================================
        # : "On the dashboard endpoint, we check for two attacks:
        # 
        # 1. PRIVILEGE ESCALATION - Detects 'is_admin=true' or 'is_superuser=true'
        #    in URL parameters. This catches users trying to elevate their role.
        #
        # 2. SQL INJECTION - Detects 'connector=OR' which is the CVE-2025-64459
        #    attack vector. Also detects 'name__icontains=NUCLEAR' which reveals
        #    hidden critical infrastructure."
        #
        # Detection Patterns:
        # - Privilege Escalation: is_admin=true, is_superuser=true
        # - SQL Injection: connector=OR, name__icontains=NUCLEAR, UNION SELECT
        # Severity: CRITICAL for both
        # =====================================================================
        elif '/dashboard/' in endpoint:
            # Privilege Escalation check (most specific first)
            if re.search(r"(?i)(is_admin=true|is_admin=1|is_superuser=true|is_superuser=1)", search_space):
                attack_detected = 'Privilege Escalation (CVE-2025-64459)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE ACTION: Block IP, invalidate compromised session, review session logs'
                reverse_action = f'Unblock IP {ip_address}, restore legitimate session if needed'
            # SQL Injection check
            elif re.search(r"(?i)(connector=OR|name__icontains=NUCLEAR)", search_space):
                attack_detected = 'SQL Injection - Filter Bypass (CVE-2025-64459)'
                severity = 'CRITICAL'
                recommended_action = 'Block IP immediately, review database access logs, check for data exfiltration'
                reverse_action = f'Unblock IP {ip_address} and restore session if needed'
            elif re.search(r"(?i)(UNION\s+SELECT|1=1|\'|\"|--)", search_space):
                attack_detected = 'SQL Injection'
                severity = 'HIGH'
                recommended_action = 'Block IP, audit database queries, check for compromised data'
                reverse_action = f'Unblock IP {ip_address}'
        
        # =====================================================================
        # VULNERABILITY DETECTION #5, #6, #7: UPLOAD VULNERABILITIES
        # Endpoint: /upload/
        # =====================================================================
        # : "The upload endpoint has three vulnerability detections:
        #
        # 1. XXE (XML External Entity) - We scan the POST body for <!ENTITY
        #    or SYSTEM file:// patterns. This catches XML injection attacks.
        #
        # 2. UNRESTRICTED FILE UPLOAD (CWE-434) - We check uploaded file
        #    extensions against a dangerous list: .php, .exe, .sh, .py, etc.
        #
        # 3. FILE OVERWRITE - We check if a file with the same name already
        #    exists in the media folder. If so, it's an overwrite attack."
        #
        # Detection Patterns:
        # - XXE: <!ENTITY, <!DOCTYPE.*SYSTEM, SYSTEM "file://
        # - Dangerous Extensions: .php, .exe, .sh, .bat, .jsp, .asp, .py
        # - Overwrite: FileSystemStorage.exists(filename)
        # =====================================================================
        elif '/upload/' in endpoint:            
            # XXE Detection (Check POST body for XML entities)
            if re.search(r"(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|SYSTEM\s+[\"']file://)", body_content):
                attack_detected = 'XXE (XML External Entity)'
                severity = 'CRITICAL'
                recommended_action = 'Block IP immediately, check for file system access, review uploaded files'
                reverse_action = f'Unblock IP {ip_address}, delete uploaded files'
            # Dangerous File Extension Detection
            elif request.method == 'POST' and request.FILES:
                for file_obj in request.FILES.values():
                    fname = file_obj.name.lower()
                    dangerous_extensions = ('.php', '.exe', '.sh', '.bat', '.jsp', '.asp', '.py', '.rb', '.pl', '.cgi')
                    if fname.endswith(dangerous_extensions):
                        attack_detected = 'Unrestricted File Upload (CWE-434)'
                        severity = 'HIGH'
                        recommended_action = f'Delete uploaded file immediately, block IP, scan server for malware'
                        reverse_action = f'Unblock IP {ip_address}'
                        break
                
                # File Overwrite Detection
                if not attack_detected:
                    from django.core.files.storage import FileSystemStorage
                    fs = FileSystemStorage(location='media/')
                    for file_obj in request.FILES.values():
                        if fs.exists(file_obj.name):
                            attack_detected = 'File Overwrite Attack (CWE-434)'
                            severity = 'MEDIUM'
                            recommended_action = f'Review overwritten file: {file_obj.name}, backup original if critical'
                            reverse_action = f'Restore original file {file_obj.name} from backup'
                            break
        
        # =====================================================================
        # VULNERABILITY DETECTION #8: IDOR + UNSAFE TEMP FILES
        # Endpoint: /report/
        # =====================================================================
        # : "The report endpoint combines two vulnerabilities:
        #
        # 1. IDOR (Insecure Direct Object Reference) - We detect when any
        #    user accesses reports by ID without authorization check.
        #
        # 2. UNSAFE TEMP FILES (CWE-377) - The vulnerable code creates
        #    predictable temp files like /tmp/scada_report_temp.pdf that
        #    can be accessed by other users."
        #
        # Detection: Any request with id= parameter to /report/ endpoint
        # Severity: HIGH
        # =====================================================================
        elif '/report/' in endpoint:
            if 'id=' in full_path:
                report_id = re.search(r'id=(\d+)', full_path)
                if report_id:
                    id_val = int(report_id.group(1))
                    attack_detected = 'IDOR + Unsafe Temp Files (CWE-639, CWE-377)'
                    severity = 'HIGH'
                    recommended_action = f'Block IP, revoke session, audit accessed reports for ID {id_val}. WARNING: Predictable temp file /tmp/scada_report_temp.pdf reused across users - potential data leakage!'
                    reverse_action = f'Unblock IP {ip_address}, restore session, delete temp file'
        
        # =====================================================================
        # VULNERABILITY DETECTION #9: INSECURE DESERIALIZATION (Pickle RCE)
        # Endpoint: /deserialize/
        # =====================================================================
        # : "The deserialize endpoint is extremely dangerous.
        # ANY POST request to this endpoint is flagged as CRITICAL because
        # pickle deserialization can lead to Remote Code Execution. The
        # attacker can execute arbitrary Python code on our server."
        #
        # Detection: Any POST request to /deserialize/
        # Severity: CRITICAL (always)
        # =====================================================================
        elif '/deserialize/' in endpoint:
            if request.method == 'POST':
                attack_detected = 'Insecure Deserialization (Pickle RCE)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE: Block IP, restart server, check for RCE execution, review system logs'
                reverse_action = f'Unblock IP {ip_address}, verify no persistent access'
        
        # =====================================================================
        # VULNERABILITY DETECTION #10: SSRF (Server-Side Request Forgery)
        # Endpoint: /ssrf/ or /node_check/
        # =====================================================================
        # : "For SSRF detection, we check if the URL parameter
        # contains internal addresses like localhost, 127.0.0.1, or the
        # AWS metadata endpoint 169.254.x.x. These indicate an attacker
        # trying to access internal resources through our server."
        #
        # Detection Pattern: localhost, 127.0.0.1, file://, 0.0.0.0, 169.254
        # Severity: HIGH
        # =====================================================================
        elif '/ssrf/' in endpoint or '/node_check/' in endpoint:
            if 'url=' in search_space:
                if re.search(r"(?i)(localhost|127\.0\.0\.1|file://|0\.0\.0\.0|169\.254)", search_space):
                    attack_detected = 'SSRF (Server-Side Request Forgery)'
                    severity = 'HIGH'
                    recommended_action = 'Block IP, review internal network access logs, check for data exfiltration'
                    reverse_action = f'Unblock IP {ip_address}'
        
        # =====================================================================
        # VULNERABILITY DETECTION #11: COOKIE MANIPULATION
        # Location: detect_cookie_manipulation() function (Line ~210)
        # =====================================================================
        # : "Cookie manipulation detection checks the session
        # cookie format. Django sessions are typically 32+ characters. If
        # we see a short cookie like 'short123' or cookies with suspicious
        # characters, we flag it as an attack."
        #
        # Detection Logic:
        # - Session ID length < 20 characters
        # - Contains suspicious characters: ; < > " ' | &
        # Severity: HIGH
        # =====================================================================
        cookie_attack = self.detect_cookie_manipulation(request)
        if cookie_attack and not attack_detected:
            attack_detected = 'Cookie Manipulation'
            severity = 'HIGH'
            recommended_action = 'Revoke session, force re-authentication, block IP if repeated'
            reverse_action = f'Restore session for {ip_address}'
        
        # =====================================================================
        # GENERIC PATTERN DETECTION (Fallback)
        # =====================================================================
        # : "Finally, we have generic pattern detection for
        # common attacks like XSS, Path Traversal, and Command Injection.
        # These use regex patterns to catch attacks we haven't specifically
        # handled above."
        # =====================================================================
        if not attack_detected:
            patterns = {
                'XSS (Cross-Site Scripting)': (r"(?i)(<script[^>]*>|alert\s*\(|javascript:|onerror\s*=|onload\s*=)", 'MEDIUM', 'Block IP, sanitize input, review XSS protection'),
                'Path Traversal': (r"(?i)(\.\.\/\.\.\/|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|C:\\Windows)", 'HIGH', 'Block IP immediately, check file system access'),
                'Command Injection': (r"(?i)(;\s*(ls|cat|whoami|id|wget|curl)\s|&&\s*(ls|cat|rm|chmod)|`(ls|cat|whoami)`|\$\((ls|cat|whoami)\))", 'CRITICAL', 'Block IP, check for shell access, review system logs'),
            }
            
            for attack_name, (pattern, sev, action) in patterns.items():
                if re.search(pattern, search_space):
                    attack_detected = attack_name
                    severity = sev
                    recommended_action = action
                    reverse_action = f'Unblock IP {ip_address}'
                    break

        # =====================================================================
        # ATTACK LOGGING AND AUTO-BLOCKING
        # =====================================================================
        # : "When an attack is detected, we create an AttackLog
        # entry with all details: IP, endpoint, attack type, severity, and
        # recommended actions. For CRITICAL attacks, we automatically block
        # the IP address if auto-blocking is enabled."
        # =====================================================================
        if attack_detected:
            log_entry = AttackLog.objects.create(
                ip_address=ip_address,
                endpoint=endpoint,
                attack_type=attack_detected,
                payload=full_path[:500],
                severity=severity,
                recommended_action=recommended_action,
                reverse_action=reverse_action
            )
            print(f"!!! [{severity}] SECURITY ALERT: {attack_detected} from {ip_address} on {endpoint} !!!")
            
            # Auto-blocking for CRITICAL severity attacks
            auto_block_enabled = getattr(settings, 'ENABLE_AUTO_BLOCKING', True)
            
            if auto_block_enabled and severity == 'CRITICAL' and not BlockedIP.objects.filter(ip_address=ip_address).exists():
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    reason=f"Auto-blocked: {attack_detected}",
                    blocked_by='SYSTEM_AUTO',
                    related_log=log_entry
                )
                log_entry.action_taken = 'AUTO_BLOCKED'
                log_entry.save()
                print(f"!!! IP {ip_address} AUTOMATICALLY BLOCKED !!!")

        response = self.get_response(request)
        
        # =====================================================================
        # VULNERABILITY DETECTION #12: DIRECTORY SCANNING
        # Location: track_404_attempts() function (Line ~235)
        # =====================================================================
        # : "Directory scanning detection runs AFTER the response.
        # We track 404 errors per IP. If we see more than 20 errors in 10
        # minutes, it indicates someone is scanning our server for hidden
        # files and directories."
        # =====================================================================
        if response.status_code == 404:
            self.track_404_attempts(ip_address)
        
        return response

    # =========================================================================
    # BRUTE FORCE DETECTION FUNCTION
    # =========================================================================
    # : "This function tracks login attempts per IP address.
    # We store each attempt in the FailedLoginAttempt model and count
    # how many occurred in the last 5 minutes."
    #
    # Thresholds:
    # - 5+ attempts in 5 min = CRITICAL (auto-block)
    # - 3-4 attempts in 5 min = HIGH (warning)
    # =========================================================================
    def check_brute_force(self, ip, endpoint, request):
        """Detect brute force login attempts"""
        if '/login/' not in endpoint:
            return False, 'LOW', ''
        
        now = timezone.now()
        five_minutes_ago = now - timedelta(minutes=5)
        
        # Count recent failed attempts from this IP
        recent_attempts = FailedLoginAttempt.objects.filter(
            ip_address=ip,
            timestamp__gte=five_minutes_ago
        ).count()
        
        # Log this attempt
        if request.method in ['GET', 'POST']:
            FailedLoginAttempt.objects.create(
                ip_address=ip,
                username=request.GET.get('username') or request.POST.get('username', ''),
                endpoint=endpoint
            )
        
        if recent_attempts >= 5:
            return True, 'CRITICAL', f'IMMEDIATE: Block IP {ip} - Brute force detected ({recent_attempts} attempts in 5 minutes)'
        elif recent_attempts >= 3:
            return True, 'HIGH', f'Monitor IP {ip} closely - Multiple login attempts ({recent_attempts})'
        
        return False, 'LOW', ''
    
    # =========================================================================
    # COOKIE MANIPULATION DETECTION FUNCTION
    # =========================================================================
    # "This function validates session cookie format. Django
    # generates secure random session IDs that are typically 32 characters.
    # Short or malformed cookies indicate tampering."
    #
    # Checks:
    # - Session ID length >= 20 characters
    # - No suspicious characters (SQL injection, XSS attempts)
    # =========================================================================
    def detect_cookie_manipulation(self, request):
        """Detect suspicious cookie/session manipulation"""
        if 'sessionid' not in request.COOKIES:
            return False
        
        session_id = request.COOKIES.get('sessionid')
        
        # Check for unusual session patterns
        if len(session_id) < 20:  # Django sessions are typically longer
            return True
        
        # Check for suspicious characters
        if re.search(r'[;<>"\'\|&]', session_id):
            return True
        
        return False
    
    # =========================================================================
    # DIRECTORY SCANNING DETECTION FUNCTION
    # =========================================================================
    # "This function tracks 404 errors per IP. Attackers often
    # scan servers for common files like .git, .env, backup.sql. More than
    # 20 errors in 10 minutes indicates automated scanning."
    #
    # Threshold: 20+ 404 errors in 10 minutes = MEDIUM severity
    # =========================================================================
    def track_404_attempts(self, ip):
        """Track 404 errors for directory scanning detection"""
        now = timezone.now()
        
        if ip not in self.failed_404_attempts:
            self.failed_404_attempts[ip] = []
        
        # Add current attempt
        self.failed_404_attempts[ip].append(now)
        
        # Keep only last 10 minutes
        ten_minutes_ago = now - timedelta(minutes=10)
        self.failed_404_attempts[ip] = [
            t for t in self.failed_404_attempts[ip] 
            if t > ten_minutes_ago
        ]
        
        # If more than 20 404s in 10 minutes = directory scanning
        if len(self.failed_404_attempts[ip]) > 20:
            AttackLog.objects.create(
                ip_address=ip,
                endpoint='/multiple_404s/',
                attack_type='Directory Scanning',
                payload=f'{len(self.failed_404_attempts[ip])} 404 errors in 10 minutes',
                severity='MEDIUM',
                recommended_action=f'Block IP {ip} temporarily, review access patterns',
                reverse_action=f'Unblock IP {ip}'
            )
            # Clear counter after logging
            self.failed_404_attempts[ip] = []