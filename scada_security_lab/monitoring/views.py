from django.shortcuts import render
from .models import AttackLog

def log_viewer(request, filter_path=None):
    # Filter logs based on the path parameter
    if filter_path:
        logs = AttackLog.objects.filter(endpoint__startswith=f'/{filter_path}/').order_by('-timestamp')
    else:
        logs = AttackLog.objects.all().order_by('-timestamp')
    
    return render(request, 'monitoring/logs.html', {
        'logs': logs,
        'filter_path': filter_path,
    })