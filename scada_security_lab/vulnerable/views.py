import urllib.request
from lxml import etree # For the XXE vulnerability
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, FileResponse
from core.models import Device, MaintenanceLog, DiagnosticReport
from django.db.models import Q
from reportlab.pdfgen import canvas
from core.models import DiagnosticResult


# SCENARIO 1: Authentication Bypass
# Vulnerability: Accepts dictionary expansion (**request.GET)
# Attack: /vulnerable/login/?username=admin&password=wrong&is_admin=True
def vulnerable_logout(request):
    request.session.flush()
    return redirect('vulnerable_login')

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
    
    # GET: Auth bypass vulnerability
    if request.method == "GET":
        if 'username' in request.GET:
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
                print("DEBUG: LOGIN SUCCESS - Admin access granted via exploit!")
                request.session['user'] = user_data
                return redirect('vulnerable_dashboard')
            else:
                print("DEBUG: LOGIN FAILED - is_admin was not True")
                # FIX: Stay on the same page, don't create a new response
                error_msg = f"Login Failed: You are not an admin. (Server saw is_admin={user_data.get('is_admin')})"
                return render(request, 'vulnerable/login.html', {'error': error_msg})
                
    return render(request, 'vulnerable/login.html')

# SCENARIO 2: Data Exfiltration via Filter Injection
# Vulnerability: Unsafe filter construction allowing OR logic
# Attack: /vulnerable/dashboard/?connector=OR&is_locked_out=True
def vulnerable_dashboard(request):
    # Ensure user is logged in (from Scenario 1)
    if 'user' not in request.session:
        return redirect('vulnerable_login')

    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # Admin sees ALL devices (including Maintenance), regular users only see Operational
    if is_admin:
        # Admin can use SQL injection to reveal hidden devices
        connector = request.GET.get('connector', 'AND')
        filter_params = request.GET.copy()
        if 'connector' in filter_params:
            del filter_params['connector']
        
        # Default: Admin only sees non-locked devices (is_locked_out=False)
        query = Q(is_locked_out=False)
        
        # THE BUG: Admin can inject filters with OR connector
        # Attack: ?connector=OR&is_locked_out=True reveals locked devices (NUCLEAR + toggled maintenance)
        for key, value in filter_params.items():
            if connector == 'OR':
                query |= Q(**{key: value})
            else:
                query &= Q(**{key: value})
        
        devices = Device.objects.filter(query)
    else:
        # Regular users only see Operational devices (can't see Maintenance or locked)
        devices = Device.objects.filter(status='Operational', is_locked_out=False)
    
    context = {
        'devices': devices,
        'user': user_data,
        'is_admin': is_admin
    }
    return render(request, 'vulnerable/dashboard.html', context)

# Vulnerabilities C (Overwrite), E (Bad File Type), G (XXE)
@csrf_exempt # Disable Django's built-in protection for this view to make hacking easier
def vulnerable_upload(request):
    context = {'status': 'Waiting for upload...'}
    
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # VULNERABILITY C: File Overwrite
        # We save the file to 'media/' using its original name.
        # If 'hack.txt' exists, this overwrites it without warning.
        fs = FileSystemStorage(location='media/')
        if fs.exists(uploaded_file.name):
            fs.delete(uploaded_file.name) # Explicitly delete old file to allow overwrite
        
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(filename)
        
        context['status'] = f"File uploaded successfully: {filename}"
        
        # VULNERABILITY G: XXE Injection
        # If it is an XML file, we parse it UNSAFELY
        if filename.endswith('.xml'):
            try:
                # DANGER: resolve_entities=True allows the XML to read local system files
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

# Vulnerabilities A (IDOR) & D (Unsafe Temp Files)
def vulnerable_report(request):
    # VULNERABILITY A: IDOR
    # We take the 'id' directly from the URL.
    # We do NOT check if the logged-in user owns this report.
    report_id = request.GET.get('id', 1)
    
    # Fetch the report (or crash if not found - simpler for demo)
    try:
        report_obj = DiagnosticReport.objects.get(id=report_id)
    except DiagnosticReport.DoesNotExist:
        return HttpResponse("Report not found", status=404)

    # VULNERABILITY D: Unsafe Temp Files
    # We use a static, predictable filename in a shared directory.
    # An attacker knows this path exists: /tmp/scada_report_temp.pdf
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

# CAPABILITY: Place device in maintenance / Release lock
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
                # calling get_data() triggers the vulnerability.
                temp_result = DiagnosticResult(serialized_data=payload)
                
                # VULNERABILITY
                data = temp_result.get_data()
                
                status = "Object Deserialized Successfully!"
                output = f"Decoded Data: {data}"
            except Exception as e:
                status = "CRITICAL ERROR: Deserialization crashed the engine."
                output = str(e)

    return render(request, 'vulnerable/deserialize.html', {'status': status, 'output': output})

# Vulnerability F: SSRF (Server-Side Request Forgery)
# Scenario: A feature to fetch "remote status logs" from other SCADA nodes.
# Attack: User enters "http://127.0.0.1:8000/admin/" or internal IPs to scan ports.
def vulnerable_ssrf(request):
    status_content = "Enter a URL to check remote node status."
    
    if request.method == "POST":
        target_url = request.POST.get('url')
        if target_url:
            try:
                # VULNERABILITY: No whitelist, no filtering.
                # The server performs the request on behalf of the user.
                with urllib.request.urlopen(target_url, timeout=5) as response:
                    status_content = f"Status: {response.status}\n\nContent:\n{response.read().decode('utf-8')[:500]}..."
            except Exception as e:
                status_content = f"Error fetching URL: {str(e)}"
    
    return render(request, 'vulnerable/ssrf.html', {'content': status_content})


# Maintenance Mode Interface
def maintenance_interface(request):
    """
    SCADA Maintenance Mode Interface
    Shows devices in maintenance, lockout status, technician assignments, and logs
    """
    if 'user' not in request.session:
        return redirect('vulnerable_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # Get devices in maintenance
    maintenance_devices = Device.objects.filter(status='Maintenance').order_by('-is_locked_out', 'name')
    
    # Get recent maintenance logs (last 50)
    recent_logs = MaintenanceLog.objects.select_related('device').order_by('-timestamp')[:50]
    
    # Get all technicians from logs (for assignment dropdown)
    technicians = MaintenanceLog.objects.values_list('technician_name', flat=True).distinct()
    
    # Statistics
    stats = {
        'total_maintenance': maintenance_devices.count(),
        'locked_out': maintenance_devices.filter(is_locked_out=True).count(),
        'total_logs': MaintenanceLog.objects.count(),
        'active_technicians': technicians.count()
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
    """
    Assign technician to device and create maintenance log
    VULNERABILITY: No proper authorization check, any user can assign
    """
    if 'user' not in request.session:
        return redirect('vulnerable_login')
    
    if request.method == 'POST':
        device = Device.objects.get(id=device_id)
        technician_name = request.POST.get('technician_name', 'Unknown')
        action = request.POST.get('action', 'Assigned to maintenance')
        
        # VULNERABILITY: No CSRF protection due to @csrf_exempt
        # VULNERABILITY: No admin check - any logged user can assign technicians
        
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