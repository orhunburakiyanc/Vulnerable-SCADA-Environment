from .models import AttackLog, BlockedIP, FailedLoginAttempt
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import re

class SecurityMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.failed_404_attempts = {}  # IP -> [timestamps] for directory scanning
        self.suspicious_sessions = {}  # Session -> metadata

    def __call__(self, request):
        ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')
        
        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden(
                "<h1>403 Forbidden</h1>"
                "<p>Your IP address has been blocked due to suspicious activity.</p>"
                "<p>Contact the administrator if you believe this is an error.</p>"
            )
        # 1. Capture the full URL (Query parameters included)
        full_path = request.get_full_path()
        endpoint = request.path
        
        # 2. Capture POST body (for form submissions)
        try:
            body_content = request.body.decode('utf-8', errors='ignore')
        except:
            body_content = ""

        search_space = f"{full_path} RAW_BODY: {body_content}"

        # 3. Endpoint-specific attack detection with severity and recommended actions
        attack_detected = None
        severity = 'MEDIUM'
        recommended_action = 'Review and investigate this attack'
        reverse_action = 'No action to reverse'
        
        # Check for brute force attacks
        brute_force_detected, bf_severity, bf_action = self.check_brute_force(ip_address, endpoint, request)
        if brute_force_detected:
            attack_detected = 'Brute Force Attack'
            severity = bf_severity
            recommended_action = bf_action
            reverse_action = f'Unblock IP {ip_address} and clear failed login attempts'
        
        # Login endpoint - Auth Bypass
        elif '/login/' in endpoint:
            if re.search(r"(?i)(is_admin=true|is_admin=1|superuser=)", search_space):
                attack_detected = 'Authentication Bypass (CVE-2025-64459)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE ACTION: Block IP, revoke all sessions from this IP, review authentication logs'
                reverse_action = f'Unblock IP {ip_address} if false positive'
        
        # Dashboard endpoint - Privilege Escalation + SQL Injection
        elif '/dashboard/' in endpoint:
            # Check for privilege escalation first (most specific)
            if re.search(r"(?i)(is_admin=true|is_admin=1|is_superuser=true|is_superuser=1)", search_space):
                attack_detected = 'Privilege Escalation (CVE-2025-64459)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE ACTION: Block IP, invalidate compromised session, review session logs'
                reverse_action = f'Unblock IP {ip_address}, restore legitimate session if needed'
            # Then check for SQL injection
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
        
        # Upload endpoint - Multiple vulnerabilities
        elif '/upload/' in endpoint:            
            # Check for XXE first (most specific)
            if re.search(r"(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|SYSTEM\s+[\"']file://)", body_content):
                attack_detected = 'XXE (XML External Entity)'
                severity = 'CRITICAL'
                recommended_action = 'Block IP immediately, check for file system access, review uploaded files'
                reverse_action = f'Unblock IP {ip_address}, delete uploaded files'
            # Check for file extension bypass
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
        
        # Report generation - IDOR
        elif '/report/' in endpoint:
            if 'id=' in full_path:
                report_id = re.search(r'id=(\d+)', full_path)
                if report_id:
                    id_val = int(report_id.group(1))
                    if id_val <= 10:  # Admin reports (1-10)
                        attack_detected = 'IDOR (Insecure Direct Object Reference)'
                        severity = 'HIGH'
                        recommended_action = f'Block IP, revoke session, audit accessed reports for ID {id_val}'
                        reverse_action = f'Unblock IP {ip_address}, restore session'
        
        # Deserialize endpoint - Pickle deserialization
        elif '/deserialize/' in endpoint:
            if request.method == 'POST':
                attack_detected = 'Insecure Deserialization (Pickle RCE)'
                severity = 'CRITICAL'
                recommended_action = 'IMMEDIATE: Block IP, restart server, check for RCE execution, review system logs'
                reverse_action = f'Unblock IP {ip_address}, verify no persistent access'
        
        # SSRF endpoint
        elif '/ssrf/' in endpoint or '/node_check/' in endpoint:
            if 'url=' in search_space:
                if re.search(r"(?i)(localhost|127\.0\.0\.1|file://|0\.0\.0\.0|169\.254)", search_space):
                    attack_detected = 'SSRF (Server-Side Request Forgery)'
                    severity = 'HIGH'
                    recommended_action = 'Block IP, review internal network access logs, check for data exfiltration'
                    reverse_action = f'Unblock IP {ip_address}'
        
        # Cookie manipulation detection
        cookie_attack = self.detect_cookie_manipulation(request)
        if cookie_attack and not attack_detected:
            attack_detected = 'Cookie Manipulation'
            severity = 'HIGH'
            recommended_action = 'Revoke session, force re-authentication, block IP if repeated'
            reverse_action = f'Restore session for {ip_address}'
        
        # Generic patterns (fallback)
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

        # 4. Log the attack if detected with full metadata
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
            
            # Automatic blocking for CRITICAL attacks
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
        
        # Directory scanning detection (after response)
        if response.status_code == 404:
            self.track_404_attempts(ip_address)
        
        return response
    
    def check_brute_force(self, ip, endpoint, request):
        """Detect brute force login attempts"""
        if ip == '192.168.65.1':
            return False, 'NONE', 'Localhost IP'
        if '/login/' not in endpoint:
            return False, 'LOW', ''
        
        # Track failed login attempts
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
        elif recent_attempts >=3:
            return True, 'HIGH', f'Monitor IP {ip} closely - Multiple login attempts ({recent_attempts})'
        
        return False, 'LOW', ''
    
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