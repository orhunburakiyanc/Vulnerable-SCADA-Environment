from django.db import models

class AttackLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=200) # Which page they attacked
    attack_type = models.CharField(max_length=100) # e.g., "SQL Injection"
    payload = models.TextField() # What they typed (e.g., "UNION SELECT...")

    def __str__(self):
        return f"{self.attack_type} from {self.ip_address}"