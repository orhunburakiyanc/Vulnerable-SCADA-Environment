import urllib.request
from lxml import etree # For the XXE vulnerability
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, FileResponse
from core.models import Device, MaintenanceLog, DiagnosticReport
from django.db.models import Q
from reportlab.pdfgen import canvas
from core.models import DiagnosticResult


# SQL INJECTION (CVE-2025-64459) - Scenario 1: Authentication Bypass
# Dictionary expansion vulnerability allowing admin access without credentials
# Attack: /vulnerable/login/?username=hacker&is_admin=true
def vulnerable_logout(request):
    request.session.flush()
    return redirect('vulnerable_login')

@csrf_exempt
def vulnerable_login(request):
    # POST: Normal login with Django authentication
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Store user info in session for consistency
            request.session['user'] = {
                'username': user.username,
                'is_admin': user.is_superuser
            }
            return redirect('vulnerable_dashboard')
        else:
            return render(request, 'vulnerable/login.html', {'error': 'Invalid username or password'})
    
    # GET: CVE-2025-64459 SQL Injection via _connector parameter
    if request.method == "GET":
        if 'username' in request.GET and 'connector' in request.GET:
            # CVE-2025-64459: Q() object with _connector manipulation allows SQL injection
            # Attack: /vulnerable/login/?username=hacker&connector=OR&is_superuser=True
            
            username = request.GET.get('username')
            connector = request.GET.get('connector', 'AND').upper()  # Attacker-controlled
            
            print(f"DEBUG [CVE-2025-64459]: Attempting SQL injection with connector={connector}")
            
            try:
                # Start with base query - username doesn't need to match
                query = Q(username=username)
                
                # Build additional conditions from URL parameters
                for key, value in request.GET.items():
                    if key not in ['username', 'connector']:
                        # Convert string 'True'/'False' to boolean
                        if value.lower() in ['true', '1']:
                            param_value = True
                        elif value.lower() in ['false', '0']:
                            param_value = False
                        else:
                            param_value = value
                        
                        # VULNERABILITY: connector allows OR injection
                        # Normal: username='hacker' AND is_superuser=True (fails)
                        # Attack: username='hacker' OR is_superuser=True (succeeds!)
                        if connector == 'OR':
                            query = query | Q(**{key: param_value})
                        else:
                            query = query & Q(**{key: param_value})
                
                print(f"DEBUG [CVE-2025-64459]: Query built with connector={connector}")
                
                # VULNERABLE: Execute the manipulated query
                user = User.objects.filter(query).first()
                
                if user:
                    # Successful SQL injection - login without password
                    login(request, user)
                    request.session['user'] = {
                        'username': user.username,
                        'is_admin': user.is_superuser
                    }
                    print(f"DEBUG [CVE-2025-64459]: SQL Injection successful! Logged in as {user.username} (superuser={user.is_superuser})")
                    return redirect('vulnerable_dashboard')
                else:
                    error_msg = "SQL Injection failed: No user found with those conditions"
                    print(f"DEBUG [CVE-2025-64459]: {error_msg}")
                    return render(request, 'vulnerable/login.html', {'error': error_msg})
            except Exception as e:
                error_msg = f"SQL Injection error: {str(e)}"
                print(f"DEBUG [CVE-2025-64459]: {error_msg}")
                return render(request, 'vulnerable/login.html', {'error': error_msg})
        
        # Old dictionary expansion vulnerability (kept for backward compatibility)
        elif 'username' in request.GET:
            # 1. Setup default user (Not Admin)
            user_data = {
                'username': request.GET.get('username'),
                'is_admin': False 
            }
            
            # 2. THE VULNERABILITY: Blindly update with URL params
            # This allows overwriting 'is_admin'
            new_data = request.GET.dict() # Convert QueryDict to standard dict
            user_data.update(new_data)
            
            # DEBUGGING: Print what the server sees to your terminal
            print(f"DEBUG: Current User Data: {user_data}")

            # 3. Check for Admin (Relaxed check: allows 'True', 'true', or '1')
            admin_value = str(user_data.get('is_admin')).lower()
            if admin_value in ['true', '1']:
                print("DEBUG: LOGIN SUCCESS - Admin access granted")
                request.session['user'] = user_data
                return redirect('vulnerable_dashboard')
            else:
                print("DEBUG: LOGIN FAILED - is_admin was not True")
                # FIX: Stay on the same page, don't create a new response
                error_msg = f"Login Failed: You are not an admin. (Server saw is_admin={user_data.get('is_admin')})"
                return render(request, 'vulnerable/login.html', {'error': error_msg})
                
    return render(request, 'vulnerable/login.html')

# SQL INJECTION (CVE-2025-64459) - Scenario 2: Privilege Escalation & Data Exfiltration
# URL parameters override session data + OR filter injection reveals hidden NUCLEAR devices
# Attack 1: /vulnerable/dashboard/?is_admin=true (Privilege Escalation)
# Attack 2: /vulnerable/dashboard/?connector=OR&name__icontains=NUCLEAR (Data Exfiltration)
# Attack 3: /vulnerable/dashboard/?connector=OR&is_locked_out=True
def vulnerable_dashboard(request):
    # Ensure user is logged in (from Scenario 1)
    if 'user' not in request.session:
        return redirect('vulnerable_login')

    user_data = request.session['user']
    
    # Privilege escalation vulnerability
    if 'is_superuser' in request.GET:
        superuser_value = str(request.GET.get('is_superuser')).lower()
        if superuser_value in ['true', '1']:
            user_data['is_admin'] = True
            request.session['user'] = user_data
            print(f"DEBUG: Privilege escalation! User {user_data['username']} gained admin rights via URL injection")
    
    if 'is_admin' in request.GET:
        admin_value = str(request.GET.get('is_admin')).lower()
        if admin_value in ['true', '1']:
            user_data['is_admin'] = True
            request.session['user'] = user_data
    
    is_admin = user_data.get('is_admin', False)
    
    # Admin and regular users both see only unlocked devices initially
    # SQL injection reveals locked out devices (including NUCLEAR if targeted)
    if is_admin:
        # Admin can use SQL injection to reveal locked out devices
        connector = request.GET.get('connector', 'AND')
        filter_params = request.GET.copy()
        
        for param in ['connector', 'is_admin', 'is_superuser']:
            filter_params.pop(param, None)
        
        # Default: Admin sees only operational, non-locked devices
        # VULNERABILITY: Locked out devices (including NUCLEAR) are hidden
        query = Q(is_locked_out=False)
        
        # THE BUG: Admin can inject filters with OR connector
        # Attack: ?connector=OR&is_locked_out=True reveals all locked devices
        # Attack: ?connector=OR&name__icontains=NUCLEAR reveals NUCLEAR specifically
        for key, value in filter_params.items():
            if connector == 'OR':
                query |= Q(**{key: value})
            else:
                query &= Q(**{key: value})
        
        devices = Device.objects.filter(query)
    else:
        # Regular users only see Operational, non-locked devices (hardcoded, safe)
        devices = Device.objects.filter(status='Operational', is_locked_out=False)
    
    context = {
        'devices': devices,
        'user': user_data,
        'is_admin': is_admin
    }
    return render(request, 'vulnerable/dashboard.html', context)

# VULNERABILITY C: File Overwrite (CWE-434)
# VULNERABILITY E: Unrestricted Upload of File with Dangerous Type (CWE-434)
# VULNERABILITY G: XXE Injection (CWE-611)
@csrf_exempt
def vulnerable_upload(request):
    context = {'status': 'Waiting for upload...'}
    
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # C) File Overwrite - uses original filename without validation
        fs = FileSystemStorage(location='media/')
        if fs.exists(uploaded_file.name):
            fs.delete(uploaded_file.name) # Explicitly delete old file to allow overwrite
        
        # There is no validation !!
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(filename)
        
        context['status'] = f"File uploaded successfully: {filename}"
        
        # G) XXE Injection - resolve_entities=True allows external entity attacks
        if filename.endswith('.xml'):
            try:
                parser = etree.XMLParser(resolve_entities=True)
                tree = etree.parse(file_path, parser=parser)
                root = tree.getroot()
                
                # We return the content of the XML back to the user
                # If the XML contained a system file read, the user sees the system file here.
                xml_content = etree.tostring(root, pretty_print=True).decode()
                context['xml_content'] = xml_content
            except Exception as e:
                context['xml_error'] = str(e)

    return render(request, 'vulnerable/upload.html', context)

# VULNERABILITY A: IDOR - Insecure Direct Object Reference (CWE-639)
# VULNERABILITY D: Unsafe Temporary Files (CWE-377)
def vulnerable_report(request):
    # A) IDOR - no ownership verification for report access
    report_id = request.GET.get('id', 1)
    
    # Fetch the report (or crash if not found - simpler for demo)
    try:
        report_obj = DiagnosticReport.objects.get(id=report_id)
    except DiagnosticReport.DoesNotExist:
        return HttpResponse("Report not found", status=404)

    # D) Unsafe Temp Files - predictable temp file path reused across users
    temp_filename = "/tmp/scada_report_temp.pdf"
    
    # Generate the PDF
    p = canvas.Canvas(temp_filename)
    p.drawString(100, 800, f"SCADA CONFIDENTIAL REPORT #{report_obj.id}")
    p.drawString(100, 780, f"Technician: {report_obj.technician_name}")
    p.drawString(100, 760, f"File: {report_obj.file_path}")
    p.drawString(100, 740, f"Date: {report_obj.created_at.strftime('%Y-%m-%d %H:%M')}")
    
    # Wrap content text (important for long sensitive data)
    content_lines = report_obj.content.split('\n')
    y_position = 700
    for line in content_lines[:20]:  # Limit to first 20 lines to fit on page
        p.drawString(100, y_position, line[:80])  # Truncate long lines
        y_position -= 20
        if y_position < 100:
            break
    
    p.save()
    
    # Return the file to the user
    # Ideally, we should stream it without saving, or use a unique temp name.
    return FileResponse(open(temp_filename, 'rb'), as_attachment=True, filename=f"report_{report_id}.pdf")

# VULNERABILITY 11: CSRF - Cross-Site Request Forgery (CWE-352)
@csrf_exempt
def toggle_status(request, device_id):
    # VULNERABILITY: No CSRF protection - CSRF attacks possible!
    # VULNERABILITY: No permission check - any logged-in user can toggle!
    if 'user' not in request.session:
        return redirect('vulnerable_login')
    
    # Get user info
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # Only admins should be able to toggle
    if not is_admin:
        return HttpResponse("Access Denied: Only administrators can toggle device status.", status=403)
    
    device = Device.objects.get(id=device_id)
    # Toggle device status and lock status (admin only)
    if device.status == 'Operational':
        device.status = 'Maintenance'
        device.is_locked_out = True  # Lock device when going to maintenance
    else:
        device.status = 'Operational'
        device.is_locked_out = False  # Unlock device when going back to operational
    device.save()
    
    # Check if coming from maintenance interface
    referer = request.META.get('HTTP_REFERER', '')
    if 'maintenance' in referer:
        return redirect('maintenance_interface')
    
    return redirect('vulnerable_dashboard')


# VULNERABILITY 8: Insecure Deserialization - Remote Code Execution (CWE-502)
@csrf_exempt
def vulnerable_deserialize(request):
    # Vulnerability B: Deserialization
    # Recieves base64 pickle data and runs it in an unsecure way    
    
    status = "Waiting for diagnostic payload..."
    output = ""

    if request.method == 'POST':
        payload = request.POST.get('payload')
        if payload:
            try:
                temp_result = DiagnosticResult(serialized_data=payload)
                data = temp_result.get_data()  # Pickle deserialization RCE
                #def get_data(self): THIS IS THE PROBLEM !
                #   decoded = base64.b64decode(self.serialized_data)
                #  return pickle.loads(decoded)  # VULNERABLE TO RCE!


                status = "Object Deserialized Successfully!"
                output = f"Decoded Data: {data}"
            except Exception as e:
                status = "CRITICAL ERROR: Deserialization crashed the engine."
                output = str(e)

    return render(request, 'vulnerable/deserialize.html', {'status': status, 'output': output})

# VULNERABILITY F: SSRF - Server-Side Request Forgery (CWE-918)
def vulnerable_ssrf(request):
    status_content = "Enter a URL to check remote node status."
    
    if request.method == "POST":
        target_url = request.POST.get('url')
        if target_url:
            try:
                # F) SSRF - no URL validation, server fetches any user-supplied URL
                with urllib.request.urlopen(target_url, timeout=5) as response:
                    status_content = f"Status: {response.status}\n\nContent:\n{response.read().decode('utf-8')[:500]}..."
            except Exception as e:
                status_content = f"Error fetching URL: {str(e)}"
    
    return render(request, 'vulnerable/ssrf.html', {'content': status_content})


# VULNERABILITY 10: Client-Side Authorization Bypass (CWE-602)
# VULNERABILITY 11: CSRF on maintenance actions (CWE-352)
# SQL INJECTION (CVE-2025-64459) - Scenario 2b: NUCLEAR-CORE Data Exfiltration
@csrf_exempt
def maintenance_interface(request):
    """
    Admin can see locked out devices, but NUCLEAR-CORE is hidden by policy.
    SQL injection with connector=OR reveals NUCLEAR-CORE-CONTROLLER.
    """
    if 'user' not in request.session:
        return redirect('vulnerable_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # Handle POST requests (maintenance actions) - CSRF vulnerability!
    if request.method == 'POST':
        device_id = request.POST.get('device_id')
        action = request.POST.get('action')
        technician = request.POST.get('technician', 'Unknown')
        
        try:
            device = Device.objects.get(id=device_id)
            
            if action == 'start_maintenance':
                device.status = 'Maintenance'
                device.save()
                MaintenanceLog.objects.create(device=device, technician_name=technician, action='Started Maintenance')
            elif action == 'end_maintenance':
                device.status = 'Operational'
                device.save()
                MaintenanceLog.objects.create(device=device, technician_name=technician, action='Ended Maintenance')
            elif action == 'lockout':
                device.is_locked_out = True
                device.save()
                MaintenanceLog.objects.create(device=device, technician_name=technician, action='Locked Out (LOTO)')
            elif action == 'unlock':
                device.is_locked_out = False
                device.save()
                MaintenanceLog.objects.create(device=device, technician_name=technician, action='Unlocked')
            
            return redirect('maintenance_interface')
        except Exception as e:
            pass  # Continue to render page with error
    
    if is_admin:
        # Admin sees maintenance devices with SQL injection vulnerability
        connector = request.GET.get('connector', 'AND')
        filter_params = request.GET.copy()
        
        for param in ['connector', 'is_admin', 'is_superuser']:
            filter_params.pop(param, None)
        
        # Default: Admin sees locked out devices but NUCLEAR is hidden for security
        # This simulates "need-to-know" policy - even admins can't see nuclear reactor controls
        query = Q(status='Maintenance') & ~Q(name__icontains='NUCLEAR')
        
        # VULNERABILITY: Admin can inject OR filter to reveal NUCLEAR-CORE
        # Attack: ?connector=OR&name__icontains=NUCLEAR
        for key, value in filter_params.items():
            if connector == 'OR':
                query |= Q(**{key: value})
            else:
                query &= Q(**{key: value})
        
        maintenance_devices = Device.objects.filter(query).order_by('-is_locked_out', 'name')
    else:
        # Regular users shouldn't access maintenance at all (client-side only check)
        maintenance_devices = Device.objects.none()
    
    # Get recent maintenance logs (last 50)
    recent_logs = MaintenanceLog.objects.select_related('device').order_by('-timestamp')[:50]
    
    # Get all technicians from logs (for assignment dropdown)
    technicians = MaintenanceLog.objects.values_list('technician_name', flat=True).distinct()
    
    # Statistics
    stats = {
        'total_maintenance': maintenance_devices.count(),
        'locked_out': maintenance_devices.filter(is_locked_out=True).count(),
        'total_logs': MaintenanceLog.objects.count(),
        'active_technicians': len(set(technicians))  # Count unique technicians
    }
    
    context = {
        'user': user_data,
        'is_admin': is_admin,
        'maintenance_devices': maintenance_devices,
        'recent_logs': recent_logs,
        'technicians': list(technicians),
        'stats': stats
    }
    
    return render(request, 'vulnerable/maintenance.html', context)


@csrf_exempt
def assign_technician(request, device_id):
    """CSRF vulnerability - no token validation"""
    if 'user' not in request.session:
        return redirect('vulnerable_login')
    
    if request.method == 'POST':
        device = Device.objects.get(id=device_id)
        technician_name = request.POST.get('technician_name', 'Unknown')
        action = request.POST.get('action', 'Assigned to maintenance')
        
        # Create maintenance log
        MaintenanceLog.objects.create(
            device=device,
            technician_name=technician_name,
            action=action
        )
        
        # Set device to maintenance mode if not already
        if device.status != 'Maintenance':
            device.status = 'Maintenance'
            device.is_locked_out = True
            device.save()
        
        return redirect('maintenance_interface')
    
    return redirect('maintenance_interface')