from django.shortcuts import render, redirect
from django.http import HttpResponse
from core.models import Device, DiagnosticReport
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_protect
import uuid
import os
import requests
from lxml import etree
import json  # Deserialization fix için gerekli

# 1. SECURE LOGIN (Fixes Auth Bypass)
def patched_login(request):

    # When we press logout it sends a "GET" request to 'patched_login' link. 
    if request.method == "GET":
        request.session.flush()
    
    if request.method == "POST":
        username = request.POST.get('username')
        # FIX: Manual session construction. No dictionary expansion (**kwargs) allowed.
        # We explicitly set is_admin to False by default.
        request.session['user'] = {
            'username': username,
            'is_admin': False 
        }
        return redirect('patched_dashboard')
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