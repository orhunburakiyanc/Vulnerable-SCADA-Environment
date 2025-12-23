from django.shortcuts import render
from .models import AttackLog

def log_viewer(request):
    # Fetch all logs, newest first
    logs = AttackLog.objects.all().order_by('-timestamp')
    
    return render(request, 'monitoring/logs.html', {'logs': logs})