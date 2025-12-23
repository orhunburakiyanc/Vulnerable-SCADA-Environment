from django.db import models
from django.contrib.auth.models import User

# 1. Device Model (The machines you control)
class Device(models.Model):
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100)
    # Status: 'Operational', 'Maintenance', 'Offline'
    status = models.CharField(max_length=50, default='Operational')
    is_locked_out = models.BooleanField(default=False) # LOTO (Lockout/Tagout)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

# 2. Maintenance Log (History of what happened)
class MaintenanceLog(models.Model):
    technician_name = models.CharField(max_length=100)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    action = models.CharField(max_length=255) # e.g., "Started Maintenance"
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.technician_name} -> {self.device.name}: {self.action}"

# 3. Diagnostic Report (For the file upload/download vulnerabilities)
class DiagnosticReport(models.Model):
    technician_name = models.CharField(max_length=100)
    file_path = models.CharField(max_length=255)
    content = models.TextField() # We store text content here for the XXE/Deserialization demos
    created_at = models.DateTimeField(auto_now_add=True)