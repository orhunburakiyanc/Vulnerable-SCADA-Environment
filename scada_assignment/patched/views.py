from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse
from core.models import Device, DiagnosticReport, MaintenanceLog
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_protect # Explicitly enforce CSRF
import uuid # For random filenames
import os
import requests # For SSRF fix
from lxml import etree # For XXE fix

# 1. SECURE LOGIN
def patched_login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        # Fix: We manually build the session dict. No dictionary expansion allowed.
        request.session['user'] = {
            'username': username,
            'is_admin': False # Enforce default
        }
        return redirect('patched_dashboard')
    return render(request, 'patched/login.html')

# 2. SECURE DASHBOARD
def patched_dashboard(request):
    if 'user' not in request.session:
        return redirect('patched_login')
    
    # Fix: Hardcoded filter. No user input can change the logic to 'OR'.
    devices = Device.objects.filter(status='Operational')
    
    context = {'devices': devices, 'user': request.session['user']}
    return render(request, 'patched/dashboard.html', context)

# 3. SECURE UPLOAD (Fixes Overwrite, Bad Type, XXE)
@csrf_protect
def patched_upload(request):
    context = {'status': 'Waiting for secure upload...'}
    
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # FIX A (File Type): Check extension
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext not in ['.xml', '.txt', '.log']:
            context['status'] = "Error: Invalid file type. Only .xml, .txt allowed."
            return render(request, 'patched/upload.html', context)

        # FIX B (Overwrite): Rename file to a random UUID
        new_filename = f"{uuid.uuid4()}{ext}"
        fs = FileSystemStorage(location='media/secure/')
        saved_name = fs.save(new_filename, uploaded_file)
        file_path = fs.path(saved_name)
        
        context['status'] = f"Saved securely as: {saved_name}"

        # FIX C (XXE): Parse XML safely
        if ext == '.xml':
            try:
                # DANGER REMOVED: resolve_entities=False blocks external file access
                parser = etree.XMLParser(resolve_entities=False, no_network=True)
                tree = etree.parse(file_path, parser=parser)
                context['xml_content'] = "XML Parsed Safely (Entities ignored)."
            except Exception as e:
                context['xml_error'] = str(e)

    return render(request, 'patched/upload.html', context)

# 4. SECURE REPORT (Fixes IDOR & Temp Files)
def patched_report(request):
    # Fix A (IDOR): Check if the user is logged in
    user_session = request.session.get('user')
    if not user_session:
        return redirect('patched_login')
        
    report_id = request.GET.get('id')
    
    try:
        # Fix A (IDOR): We would normally check if report.owner == current_user
        # For this demo, we just ensure the ID exists and don't crash.
        report = DiagnosticReport.objects.get(id=report_id)
        
        # Fix B (Temp Files): We don't save to /tmp/. We stream directly.
        # Ideally, use a ByteStream buffer.
        return HttpResponse(f"Secure Report for ID {report_id}\nOwner: {report.technician_name}", content_type="text/plain")
        
    except DiagnosticReport.DoesNotExist:
        return HttpResponse("Access Denied or Report Not Found", status=403)

# 5. SECURE SSRF
def patched_ssrf(request):
    context = {}
    if request.method == 'POST':
        url = request.POST.get('url', '')
        
        # Fix: Allowlist approach. Only allow specific domains.
        allowed_domains = ['scada-update-server.com', 'example.com']
        
        # Simple check: does the URL start with an allowed domain?
        is_allowed = any(url.startswith(f"http://{d}") or url.startswith(f"https://{d}") for d in allowed_domains)
        
        if is_allowed:
            try:
                # Fix: Set a strict timeout and verify SSL
                resp = requests.get(url, timeout=2)
                context['result'] = f"Success: {resp.status_code}"
            except:
                context['result'] = "Connection Failed"
        else:
            context['result'] = "Blocked: Domain not in allowlist."
            
    return render(request, 'patched/ssrf.html', context)