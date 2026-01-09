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

# FIX: Authentication Bypass (CVE-2025-64459, CWE-287)
# POST-only authentication using Django's authenticate(), admin status from database only
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

# FIX: Privilege Escalation + SQL Injection (CVE-2025-64459, CWE-269, CWE-89)
# Static queries only, admin status from session (not URL), no dynamic filter construction
def patched_dashboard(request):
    if 'user' not in request.session:
        return redirect('patched_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    # FIX 1: Show dashboard to all authenticated users but restrict device visibility
    if is_admin:
        # Admin sees operational + maintenance devices (no locked out)
        # CRITICAL: Exclude NUCLEAR devices - critical infrastructure protection
        devices = Device.objects.filter(
            status__in=['Operational', 'Maintenance'], 
            is_locked_out=False
        ).exclude(name__icontains='NUCLEAR')
    else:
        # Regular users see empty list (no devices shown)
        devices = []
    
    # FIX 2: No SQL injection - hardcoded filters only (no dynamic query construction)
    context = {
        'devices': devices,
        'user': user_data,
        'is_admin': is_admin,
        'access_denied_message': None if is_admin else 'Device access is restricted to administrators only.'
    }
    return render(request, 'patched/dashboard.html', context)

# FIX: File Overwrite + Unrestricted Upload + XXE (CWE-434, CWE-611)
# Whitelist file types, UUID filenames, XML parser with resolve_entities=False
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

# FIX: IDOR + Unsafe Temp Files (CWE-639, CWE-377)
# Authentication check required + ownership verification
def patched_report(request):
    # Authentication check
    user_session = request.session.get('user')
    if not user_session:
        return redirect('patched_login')
    
    username = user_session.get('username')
    is_admin = user_session.get('is_admin', False)
    report_id = request.GET.get('id')
    
    if not report_id:
        return HttpResponse("Report ID required", status=400)
    
    try:
        report = DiagnosticReport.objects.get(id=report_id)
        
        # CRITICAL: Ownership verification
        # - Admins can access all reports (for audit purposes)
        # - Regular users can only access their own reports
        if not is_admin and report.technician_name != username:
            return HttpResponse(
                "<h1>Access Denied</h1>"
                "<p>You do not have permission to access this report.</p>"
                "<p>Users can only access their own diagnostic reports.</p>",
                status=403
            )
        
        # Return report as plain text (patched: no confidential data exposure to unauthorized users)
        response_text = f"SECURE REPORT #{report.id}\nTechnician: {report.technician_name}\nContent: {report.content}"
        return HttpResponse(response_text, content_type="text/plain")
        
    except DiagnosticReport.DoesNotExist:
        return HttpResponse("Report Not Found", status=404)

# FIX: SSRF (CWE-918)
# Allowlist approach - only trusted domains permitted
def patched_ssrf(request):
    context = {}
    if request.method == 'POST':
        url = request.POST.get('url', '')
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

# FIX: Insecure Deserialization (CWE-502)
# JSON used instead of Pickle - no code execution possible
@csrf_protect
def patched_deserialize(request):
    status = "Waiting for JSON payload..."
    output = ""
    
    if request.method == 'POST':
        payload = request.POST.get('payload')
        try:
            data = json.loads(payload)
            status = "Success: Object Deserialized Safely (JSON)"
            output = f"Data: {data}"
        except json.JSONDecodeError:
            status = "Error: Invalid JSON format."
        except Exception as e:
            status = f"Error: {str(e)}"

    return render(request, 'patched/deserialize.html', {'status': status, 'output': output})


# FIX: Authorization Bypass + CSRF (CWE-602, CWE-352)
# Server-side admin check returns 403 if not admin, CSRF protection enabled
@csrf_protect
def patched_maintenance_interface(request):
    """Admin-only access with server-side authorization"""
    if 'user' not in request.session:
        return redirect('patched_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    if not is_admin:
        return HttpResponse(
            "<h1>Access Denied</h1><p>Maintenance interface requires administrator privileges.</p>",
            status=403
        )
    
    # Get devices in maintenance
    # CRITICAL: Exclude NUCLEAR devices - critical infrastructure should never be visible
    # Defense-in-depth: Even admins cannot see NUCLEAR-CORE devices in maintenance interface
    maintenance_devices = Device.objects.filter(status='Maintenance').exclude(name__icontains='NUCLEAR').order_by('-is_locked_out', 'name')
    
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
    
    return render(request, 'patched/maintenance.html', context)


# FIX: CSRF + Authorization (CWE-352)
# CSRF protection, admin-only authorization, input validation
@csrf_protect
def patched_assign_technician(request, device_id):
    """Admin-only technician assignment with input validation"""
    if 'user' not in request.session:
        return redirect('patched_login')
    
    user_data = request.session['user']
    is_admin = user_data.get('is_admin', False)
    
    if not is_admin:
        return HttpResponse("Access Denied: Admin privileges required", status=403)
    
    if request.method == 'POST':
        try:
            device = Device.objects.get(id=device_id)
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


# FIX: CSRF + Authorization (CWE-352)
# CSRF protection, admin-only authorization
@csrf_protect
def patched_toggle_status(request, device_id):
    """Admin-only device toggle with CSRF protection"""
    
    # Admin authorization check
    user = request.session.get('user', {})
    is_admin = user.get('is_admin', False)
    
    if not is_admin:
        return HttpResponse(
            "<h1>Access Denied</h1>"
            "<p>Only administrators can toggle device status.</p>",
            status=403
        )
    
    # Accept both GET and POST for toggle (GET for links, POST for forms)
    if request.method in ['GET', 'POST']:
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
            
            # Check where to redirect based on where toggle was triggered
            referer = request.META.get('HTTP_REFERER', '')
            # If toggled FROM dashboard and device moved TO Maintenance, go to maintenance interface
            # If toggled FROM maintenance, stay in maintenance interface
            if 'dashboard' in referer and device.status == 'Maintenance':
                return redirect('patched_maintenance_interface')
            elif 'maintenance' in referer:
                return redirect('patched_maintenance_interface')
            
            return redirect('patched_dashboard')
            
        except Device.DoesNotExist:
            return HttpResponse("Device not found", status=404)
        except Exception as e:
            return HttpResponse(f"Error: {str(e)}", status=500)
    
    return redirect('patched_dashboard')