from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from core.models import Device, DiagnosticReport, MaintenanceLog
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_protect
import uuid
import os
import requests
from lxml import etree
import json  # Deserialization fix için gerekli

# 1. SECURE LOGIN (Fixes Auth Bypass)
def patched_login(request):
    # Logout on GET request
    if request.method == "GET":
        request.session.flush()
        return render(request, 'patched/login.html')
    
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # FIX: Use Django's built-in authentication
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Manual session construction with explicit values
            request.session['user'] = {
                'username': user.username,
                'is_admin': user.is_superuser  # Only set if actually superuser
            }
            return redirect('patched_dashboard')
        else:
            return render(request, 'patched/login.html', {'error': 'Invalid username or password'})
    
    return render(request, 'patched/login.html')

# 2. SECURE DASHBOARD (Fixes SQL Injection & Data Exfiltration)
def patched_dashboard(request):
    if 'user' not in request.session:
        return redirect('patched_login')
    
    # FIX: Django ORM filter() uses parameterization automatically.
    # We deliberately ignore 'connector' or other injection attempts from URL.
    # We only show 'Operational' devices, hiding the secret/maintenance ones.
    devices = Device.objects.filter(status='Operational')
    
    context = {'devices': devices, 'user': request.session['user']}
    return render(request, 'patched/dashboard.html', context)

# 3. SECURE UPLOAD (Fixes Overwrite, Bad Type, XXE)
@csrf_protect
def patched_upload(request):
    context = {'status': 'Waiting for secure upload...'}
    
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # FIX A (File Type): Whitelist allowed extensions
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext not in ['.xml', '.txt', '.log']:
            context['status'] = "Error: Invalid file type. Only .xml, .txt allowed."
            return render(request, 'patched/upload.html', context)

        # FIX B (Overwrite): Use UUID to prevent overwriting existing files
        new_filename = f"{uuid.uuid4()}{ext}"
        fs = FileSystemStorage(location='media/secure/')
        saved_name = fs.save(new_filename, uploaded_file)
        file_path = fs.path(saved_name)
        
        context['status'] = f"Saved securely as: {saved_name}"

        # FIX C (XXE): Parse XML safely (disable entity resolution)
        if ext == '.xml':
            try:
                # resolve_entities=False and no_network=True blocks XXE
                parser = etree.XMLParser(resolve_entities=False, no_network=True)
                tree = etree.parse(file_path, parser=parser)
                context['xml_content'] = "XML Parsed Safely (External Entities ignored)."
            except Exception as e:
                context['xml_error'] = str(e)

    return render(request, 'patched/upload.html', context)

# 4. SECURE REPORT (Fixes IDOR & Unsafe Temp Files)
def patched_report(request):
    # Fix A (IDOR): Check authentication
    user_session = request.session.get('user')
    if not user_session:
        return redirect('patched_login')
        
    report_id = request.GET.get('id')
    
    try:
        # In a real app, we would also check: if report.owner == user_session['username']
        report = DiagnosticReport.objects.get(id=report_id)
        
        # Fix B (Temp Files): Return content directly via memory (Stream), no temp file on disk.
        response_text = f"SECURE REPORT #{report.id}\nTechnician: {report.technician_name}\nContent: {report.content}"
        return HttpResponse(response_text, content_type="text/plain")
        
    except DiagnosticReport.DoesNotExist:
        return HttpResponse("Access Denied or Report Not Found", status=403)

# 5. SECURE SSRF (Fixes Arbitrary Remote Access)
def patched_ssrf(request):
    context = {}
    if request.method == 'POST':
        url = request.POST.get('url', '')
        
        # FIX: Allowlist approach.
        allowed_domains = ['scada-update-server.com', 'example.com']
        
        # Check if URL starts with permitted domains
        is_allowed = any(url.startswith(f"http://{d}") or url.startswith(f"https://{d}") for d in allowed_domains)
        
        if is_allowed:
            try:
                # Set timeout to prevent DoS
                resp = requests.get(url, timeout=2)
                context['result'] = f"Success: {resp.status_code} - {resp.reason}"
            except Exception as e:
                context['result'] = f"Connection Failed: {str(e)}"
        else:
            context['result'] = "Blocked: Domain not in allowlist."
            
    return render(request, 'patched/ssrf.html', context)

# 6. SECURE DIAGNOSTICS (Fixes Deserialization)
@csrf_protect
def patched_deserialize(request):
    status = "Waiting for JSON payload..."
    output = ""
    
    if request.method == 'POST':
        payload = request.POST.get('payload')
        try:
            # JSON is used instead of Pickle.
            # JSON is a data-interchange format and cannot execute code.
            data = json.loads(payload)
            status = "Success: Object Deserialized Safely (JSON)"
            output = f"Data: {data}"
        except json.JSONDecodeError:
            status = "Error: Invalid JSON format."
        except Exception as e:
            status = f"Error: {str(e)}"

    return render(request, 'patched/deserialize.html', {'status': status, 'output': output})


# 7. SECURE MAINTENANCE INTERFACE
@csrf_protect
def patched_maintenance_interface(request):
    """
    Secure Maintenance Mode Interface
    - CSRF protection enabled
    - Admin-only access control
    - Proper authorization checks
    """
    if 'user' not in request.session:
        return redirect('patched_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # FIX: Admin-only access for maintenance interface
    if not is_admin:
        return HttpResponse(
            "<h1>Access Denied</h1><p>Maintenance interface requires administrator privileges.</p>",
            status=403
        )
    
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
    
    return render(request, 'patched/maintenance.html', context)


@csrf_protect
def patched_assign_technician(request, device_id):
    """
    Secure technician assignment
    - CSRF protection enabled
    - Admin-only authorization
    - Input validation
    """
    if 'user' not in request.session:
        return redirect('patched_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # FIX: Admin-only authorization check
    if not is_admin:
        return HttpResponse("Access Denied: Admin privileges required", status=403)
    
    if request.method == 'POST':
        try:
            device = Device.objects.get(id=device_id)
            
            # FIX: Input validation
            technician_name = request.POST.get('technician_name', '').strip()
            action = request.POST.get('action', '').strip()
            
            if not technician_name or len(technician_name) < 2:
                return HttpResponse("Invalid technician name", status=400)
            
            if not action or len(action) < 5:
                return HttpResponse("Invalid action description", status=400)
            
            # Sanitize inputs (prevent SQL injection)
            technician_name = technician_name[:100]  # Limit length
            action = action[:255]  # Limit length
            
            # Create maintenance log with validated data
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
            
            return redirect('patched_maintenance_interface')
            
        except Device.DoesNotExist:
            return HttpResponse("Device not found", status=404)
        except Exception as e:
            return HttpResponse(f"Error: {str(e)}", status=500)
    
    return redirect('patched_maintenance_interface')


@csrf_protect
def patched_toggle_status(request, device_id):
    """Toggle device status - SECURE VERSION with CSRF protection"""
    
    # Admin authorization check
    user = request.session.get('user', {})
    is_admin = user.get('is_admin', False)
    
    if not is_admin:
        return HttpResponse(
            "<h1>Access Denied</h1>"
            "<p>Only administrators can toggle device status.</p>",
            status=403
        )
    
    if request.method == 'POST':
        try:
            device = Device.objects.get(id=device_id)
            
            # Toggle device status and lock status
            if device.status == 'Operational':
                device.status = 'Maintenance'
                device.is_locked_out = True
            else:
                device.status = 'Operational'
                device.is_locked_out = False
            
            device.save()
            
            # Check if coming from maintenance interface
            referer = request.META.get('HTTP_REFERER', '')
            if 'maintenance' in referer:
                return redirect('patched_maintenance_interface')
            
            return redirect('patched_dashboard')
            
        except Device.DoesNotExist:
            return HttpResponse("Device not found", status=404)
        except Exception as e:
            return HttpResponse(f"Error: {str(e)}", status=500)
    
    return redirect('patched_dashboard')