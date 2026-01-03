from django.db import models
from django.utils import timezone

class AttackLog(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    ACTION_CHOICES = [
        ('NONE', 'No action taken'),
        ('BLOCKED', 'IP Blocked'),
        ('SESSION_REVOKED', 'Session Revoked'),
        ('REVIEWED', 'Reviewed by admin'),
        ('AUTO_BLOCKED', 'Automatically Blocked'),
    ]
    
    # Existing fields
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=200)
    attack_type = models.CharField(max_length=100)
    payload = models.TextField()
    
    # New actionable fields
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    recommended_action = models.TextField(default='Review and investigate this attack')
    action_taken = models.CharField(max_length=50, choices=ACTION_CHOICES, default='NONE')
    reverse_action = models.TextField(default='No action to reverse')
    
    # Resolution tracking
    is_resolved = models.BooleanField(default=False)
    admin_notes = models.TextField(blank=True, null=True)
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolved_by = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.attack_type} from {self.ip_address}"
    
    def mark_resolved(self, admin_user='admin', notes=''):
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.resolved_by = admin_user
        if notes:
            self.admin_notes = notes
        self.save()


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField()
    blocked_by = models.CharField(max_length=100, default='admin')
    related_log = models.ForeignKey(AttackLog, on_delete=models.SET_NULL, null=True, blank=True)
    is_permanent = models.BooleanField(default=False)
    unblock_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-blocked_at']
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
    
    def __str__(self):
        return f"{self.ip_address} (blocked {self.blocked_at})"
    
    def unblock_command(self):
        return f"Remove IP {self.ip_address} from firewall rules or delete BlockedIP record"


class FailedLoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=100, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    endpoint = models.CharField(max_length=200)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.ip_address} at {self.timestamp}"