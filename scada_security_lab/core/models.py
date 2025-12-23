from django.db import models
from django.contrib.auth.models import User
import pickle
import base64

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

# 4. Diagnostic Result (Deserialization Vulnerability)
class DiagnosticResult(models.Model):
    """
    Vulnerability B: Deserialization Bug
    Uses pickle for serialization - DANGEROUS!
    """
    # Establishing a connection to DiagnosticReport 
    report = models.ForeignKey(DiagnosticReport, on_delete=models.CASCADE, related_name='results')
    serialized_data = models.TextField(help_text='Base64-encoded pickle data')
    created_at = models.DateTimeField(auto_now_add=True)

    def set_data(self, data_dict):
        """Serialize data using pickle (VULNERABLE)"""
        pickled = pickle.dumps(data_dict)
        self.serialized_data = base64.b64encode(pickled).decode('utf-8')

    def get_data(self):
        """
        VULNERABLE: Deserialize using pickle
        Corrupted/malicious payload can crash or execute code!
        """
        if not self.serialized_data:
            return None
        try:
            decoded = base64.b64decode(self.serialized_data)
            return pickle.loads(decoded)  # VULNERABLE!
        except Exception as e:
            return str(e)