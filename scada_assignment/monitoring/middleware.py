from .models import AttackLog
import re

class SecurityMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Capture the full URL (Query parameters included)
        full_path = request.get_full_path()
        
        # 2. Capture POST body (for form submissions)
        try:
            body_content = request.body.decode('utf-8', errors='ignore')
        except:
            body_content = ""

        # --- DÜZELTME BURADA YAPILDI ---
        # Eski hatalı kod: search_space = f"{full_path} | {body_content}"
        # Yeni kod: Araya ' | ' yerine ' RAW_BODY: ' gibi zararsız bir metin koyduk.
        # Böylece regex kuralı kendi kendisini tetiklemez.
        search_space = f"{full_path} RAW_BODY: {body_content}"

        # 3. Define Attack Signatures (Regex patterns)
        signatures = {
            'Auth Bypass': r"(?i)(superuser=|is_admin=|admin=true)", 
            'SQL Injection': r"(?i)(UNION\s+SELECT|OR\s+1=1|connector=OR|--)",
            'XSS / Scripting': r"(?i)(<script>|alert\(|javascript:)",
            'Path Traversal / XXE': r"(?i)(\.\./|/etc/passwd|<!ENTITY)",
            # Command Injection pattern looks for | character, so we removed it from search_space construction
            'Command Injection': r"(?i)(; ls|&&|\|)",
        }

        # 4. Check for matches
        for attack_name, pattern in signatures.items():
            if re.search(pattern, search_space):
                # LOG THE ATTACK
                AttackLog.objects.create(
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    endpoint=request.path,
                    attack_type=attack_name,
                    payload=full_path  # Save the URL so you can see what happened
                )
                print(f"!!! SECURITY ALERT: {attack_name} detected !!!")
                break 

        response = self.get_response(request)
        return response