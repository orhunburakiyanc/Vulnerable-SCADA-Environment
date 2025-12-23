import os
from lxml import etree # For the XXE vulnerability
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, FileResponse
from core.models import Device, MaintenanceLog, DiagnosticReport
from django.db.models import Q
from reportlab.pdfgen import canvas

# SCENARIO 1: Authentication Bypass
# Vulnerability: Accepts dictionary expansion (**request.GET)
# Attack: /vulnerable/login/?username=admin&password=wrong&superuser=True
def vulnerable_login(request):
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
                return HttpResponse(f"Login Failed: You are not an admin. (Server saw is_admin={user_data.get('is_admin')})")
                
    return render(request, 'vulnerable/login.html')

# SCENARIO 2: Data Exfiltration via Filter Injection
# Vulnerability: Unsafe filter construction allowing OR logic
# Attack: /vulnerable/dashboard/?connector=OR&is_locked_out=True
def vulnerable_dashboard(request):
    # Ensure user is logged in (from Scenario 1)
    if 'user' not in request.session:
        return redirect('vulnerable_login')

    # Default: Show only devices in "Operational" status
    # We want to filter: WHERE status = 'Operational' AND ...
    filters = {'status': 'Operational'}
    
    # THE BUG: We take the 'connector' from the URL (AND/OR)
    # and we take arbitrary filters from the URL parameters
    connector = request.GET.get('connector', 'AND')
    
    # Remove 'connector' from the dict so we can use the rest as filters
    filter_params = request.GET.copy()
    if 'connector' in filter_params:
        del filter_params['connector']

    # Building the query dynamically (VULNERABLE)
    # This simulates the "Dictionary Expansion" logic mentioned in your prompt
    # If connector is OR, it bypasses the 'Operational' check if the second condition is met
    
    query = Q(status='Operational')
    
    for key, value in filter_params.items():
        # Attacker can inject ANY field here, e.g., 'is_locked_out': True
        # If connector is OR, query becomes: (status='Operational') OR (is_locked_out=True)
        if connector == 'OR':
            query |= Q(**{key: value})
        else:
            query &= Q(**{key: value})

    devices = Device.objects.filter(query)
    
    context = {
        'devices': devices,
        'user': request.session['user']
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
    p.drawString(100, 760, f"Data: {report_obj.content}")
    p.save()
    
    # Return the file to the user
    # Ideally, we should stream it without saving, or use a unique temp name.
    return FileResponse(open(temp_filename, 'rb'), as_attachment=True, filename=f"report_{report_id}.pdf")