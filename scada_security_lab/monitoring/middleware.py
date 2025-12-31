from .models import AttackLog
import re

class SecurityMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Capture the full URL (Query parameters included)
        full_path = request.get_full_path()
        endpoint = request.path
        
        # 2. Capture POST body (for form submissions)
        try:
            body_content = request.body.decode('utf-8', errors='ignore')
        except:
            body_content = ""

        search_space = f"{full_path} RAW_BODY: {body_content}"

        # 3. Endpoint-specific attack detection
        attack_detected = None
        
        # Login endpoint - Auth Bypass
        if '/login/' in endpoint:
            if re.search(r"(?i)(is_admin=true|is_admin=1|superuser=)", search_space):
                attack_detected = 'Authentication Bypass (CVE-2025-64459)'
        
        # Dashboard endpoint - SQL Injection via OR connector
        elif '/dashboard/' in endpoint:
            if re.search(r"(?i)(connector=OR|is_locked_out=True)", search_space):
                attack_detected = 'SQL Injection - Filter Bypass (CVE-2025-64459)'
            elif re.search(r"(?i)(UNION\s+SELECT|1=1|\'|\"|--)", search_space):
                attack_detected = 'SQL Injection'
        
        # Upload endpoint - Multiple vulnerabilities
        elif '/upload/' in endpoint:
            # Check for XXE first (most specific)
            if re.search(r"(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|SYSTEM\s+[\"']file://)", body_content):
                attack_detected = 'XXE (XML External Entity)'
            # Check for file extension bypass (only dangerous extensions)
            elif request.method == 'POST' and request.FILES:
                for file_obj in request.FILES.values():
                    fname = file_obj.name.lower()
                    # CWE-434: Unrestricted Upload of File with Dangerous Type
                    dangerous_extensions = ('.php', '.exe', '.sh', '.bat', '.jsp', '.asp', '.py', '.rb', '.pl', '.cgi')
                    if fname.endswith(dangerous_extensions):
                        attack_detected = 'Unrestricted File Upload (CWE-434)'
                        break
        
        # Report generation - IDOR and Temp File vulnerabilities
        elif '/report/' in endpoint:
            # IDOR: Trying to access other users' reports
            if 'id=' in full_path:
                report_id = re.search(r'id=(\d+)', full_path)
                if report_id:
                    id_val = int(report_id.group(1))
                    # Reports 1-50 are user reports, 51+ are admin (especially 51 with root password)
                    if id_val > 50:
                        attack_detected = 'IDOR (Insecure Direct Object Reference)'
        
        # Deserialize endpoint - Pickle deserialization
        elif '/deserialize/' in endpoint:
            if request.method == 'POST':
                attack_detected = 'Insecure Deserialization (Pickle RCE)'
        
        # SSRF endpoint
        elif '/ssrf/' in endpoint or '/node_check/' in endpoint:
            if 'url=' in search_space:
                # Check for internal/file URLs
                if re.search(r"(?i)(localhost|127\.0\.0\.1|file://|0\.0\.0\.0|169\.254)", search_space):
                    attack_detected = 'SSRF (Server-Side Request Forgery)'
        
        # Generic patterns (fallback)
        if not attack_detected:
            patterns = {
                'XSS (Cross-Site Scripting)': r"(?i)(<script[^>]*>|alert\s*\(|javascript:|onerror\s*=|onload\s*=)",
                'Path Traversal': r"(?i)(\.\.\/\.\.\/|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|C:\\Windows)",
                'Command Injection': r"(?i)(;\s*(ls|cat|whoami|id|wget|curl)\s|&&\s*(ls|cat|rm|chmod)|`(ls|cat|whoami)`|\$\((ls|cat|whoami)\))",
            }
            
            for attack_name, pattern in patterns.items():
                if re.search(pattern, search_space):
                    attack_detected = attack_name
                    break

        # 4. Log the attack if detected
        if attack_detected:
            AttackLog.objects.create(
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                endpoint=endpoint,
                attack_type=attack_detected,
                payload=full_path[:500]  # Limit payload length
            )
            print(f"!!! SECURITY ALERT: {attack_detected} detected on {endpoint} !!!")

        response = self.get_response(request)
        return response