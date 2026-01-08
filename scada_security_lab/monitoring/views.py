from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import AttackLog, BlockedIP, FailedLoginAttempt
import csv

def log_viewer(request, filter_path=None):
    """Display attack logs with severity, recommended actions, and admin controls"""
    
    # SECURITY MISCONFIGURATION (OWASP A05:2021)
    # Patched version requires admin authentication to view sensitive security logs
    # Vulnerable version allows any user to access attack logs (information disclosure)
    if filter_path == 'patched':
        user = request.session.get('user', {})
        if not user.get('is_admin'):
            return HttpResponse(
                "<h1>Access Denied</h1><p>Security monitoring logs require administrator privileges.</p>"
                "<p><a href='/patched/login/'>Login as admin</a></p>",
                status=403
            )
    # No auth check for vulnerable version - SECURITY MISCONFIGURATION!
    
    # Get filter parameters
    severity_filter = request.GET.get('severity', '')
    action_filter = request.GET.get('action', '')
    resolved_filter = request.GET.get('resolved', '')
    
    # Base queryset
    if filter_path:
        logs = AttackLog.objects.filter(endpoint__startswith=f'/{filter_path}/').order_by('-timestamp')
    else:
        logs = AttackLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if severity_filter:
        logs = logs.filter(severity=severity_filter)
    if action_filter:
        logs = logs.filter(action_taken=action_filter)
    if resolved_filter == 'yes':
        logs = logs.filter(is_resolved=True)
    elif resolved_filter == 'no':
        logs = logs.filter(is_resolved=False)
    
    # Get statistics
    total_logs = logs.count()
    critical_count = AttackLog.objects.filter(severity='CRITICAL').count()
    high_count = AttackLog.objects.filter(severity='HIGH').count()
    unresolved_count = AttackLog.objects.filter(is_resolved=False).count()
    blocked_ips_count = BlockedIP.objects.filter(is_permanent=False).count()
    
    # Get blocked IPs list
    blocked_ips = BlockedIP.objects.all().order_by('-blocked_at')
    
    # Get user info from session
    user = request.session.get('user', {})
    user_is_admin = user.get('is_admin', False)
    
    context = {
        'logs': logs[:100],  # Limit to 100 for performance
        'total_logs': total_logs,
        'critical_count': critical_count,
        'high_count': high_count,
        'unresolved_count': unresolved_count,
        'blocked_ips_count': blocked_ips_count,
        'blocked_ips': blocked_ips[:20],
        'filter_path': filter_path,
        'severity_filter': severity_filter,
        'action_filter': action_filter,
        'resolved_filter': resolved_filter,
        'user': user,
        'is_admin': user_is_admin,
        'user_is_admin': user_is_admin,  # For JavaScript check
    }
    
    return render(request, 'monitoring/logs.html', context)

def block_ip_action(request, log_id):
    """Block IP address associated with an attack log (Admin only)"""
    # Check admin permission
    user = request.session.get('user', {})
    if not user.get('is_admin'):
        return JsonResponse({'status': 'error', 'message': 'Unauthorized: Admin access required'}, status=403)
    
    log = get_object_or_404(AttackLog, id=log_id)
    
    # Check if already blocked
    if BlockedIP.objects.filter(ip_address=log.ip_address).exists():
        return JsonResponse({'status': 'error', 'message': 'IP already blocked'})
    
    # Create block entry
    admin_user = user.get('username', 'manual_admin')
    BlockedIP.objects.create(
        ip_address=log.ip_address,
        reason=f"Manual block for {log.attack_type}",
        blocked_by=admin_user,
        related_log=log
    )
    
    # Update log
    log.action_taken = 'BLOCKED'
    log.save()
    
    return JsonResponse({'status': 'success', 'message': f'IP {log.ip_address} blocked successfully'})

def unblock_ip_action(request, blocked_ip_id):
    """Unblock a previously blocked IP (Admin only)"""
    # Check admin permission
    user = request.session.get('user', {})
    if not user.get('is_admin'):
        return JsonResponse({'status': 'error', 'message': 'Unauthorized: Admin access required'}, status=403)
    blocked_ip = get_object_or_404(BlockedIP, id=blocked_ip_id)
    ip_address = blocked_ip.ip_address
    
    # Delete block entry
    blocked_ip.delete()
    
    # Update related log if exists
    if blocked_ip.related_log:
        blocked_ip.related_log.action_taken = 'REVIEWED'
        blocked_ip.related_log.save()
    
    return JsonResponse({'status': 'success', 'message': f'IP {ip_address} unblocked successfully'})

def revoke_session_action(request, log_id):
    """Revoke session for an attack (Admin only)"""
    # Check admin permission
    user = request.session.get('user', {})
    if not user.get('is_admin'):
        return JsonResponse({'status': 'error', 'message': 'Unauthorized: Admin access required'}, status=403)
    
    log = get_object_or_404(AttackLog, id=log_id)
    
    # Update log
    log.action_taken = 'SESSION_REVOKED'
    log.save()
    
    return JsonResponse({
        'status': 'success', 
        'message': f'Session revoked for IP {log.ip_address}. User must re-authenticate.'
    })

def resolve_log_action(request, log_id):
    """Mark an attack log as resolved (Admin only)"""
    # Check admin permission
    user = request.session.get('user', {})
    if not user.get('is_admin'):
        return JsonResponse({'status': 'error', 'message': 'Unauthorized: Admin access required'}, status=403)
    
    log = get_object_or_404(AttackLog, id=log_id)
    
    # Get admin notes and username from session
    admin_notes = request.GET.get('notes', '')
    admin_user = user.get('username', 'manual_admin')
    
    # Mark as resolved (correct parameter order: admin_user, notes)
    log.mark_resolved(admin_user, admin_notes)
    log.action_taken = 'REVIEWED'
    log.save()
    
    return JsonResponse({'status': 'success', 'message': 'Log marked as resolved'})

def export_logs(request):
    """Export logs to CSV (Admin only)"""
    # Check admin permission
    user = request.session.get('user', {})
    if not user.get('is_admin'):
        return HttpResponse(
            "<h1>Access Denied</h1><p>CSV export requires administrator privileges.</p>",
            status=403
        )
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="attack_logs.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'IP Address', 'Endpoint', 'Attack Type', 'Severity', 
                     'Recommended Action', 'Action Taken', 'Is Resolved', 'Admin Notes'])
    
    logs = AttackLog.objects.all().order_by('-timestamp')
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.ip_address,
            log.endpoint,
            log.attack_type,
            log.severity,
            log.recommended_action,
            log.action_taken,
            'Yes' if log.is_resolved else 'No',
            log.admin_notes or ''
        ])
    
    return response

def dashboard_stats(request):
    """Return statistics for monitoring dashboard"""
    from django.db.models import Count
    from datetime import timedelta
    
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_attacks': AttackLog.objects.count(),
        'attacks_24h': AttackLog.objects.filter(timestamp__gte=last_24h).count(),
        'critical_unresolved': AttackLog.objects.filter(severity='CRITICAL', is_resolved=False).count(),
        'blocked_ips': BlockedIP.objects.count(),
        'failed_logins_24h': FailedLoginAttempt.objects.filter(timestamp__gte=last_24h).count(),
        'attack_types': list(AttackLog.objects.values('attack_type').annotate(count=Count('attack_type')).order_by('-count')[:10]),
        'severity_breakdown': {
            'CRITICAL': AttackLog.objects.filter(severity='CRITICAL').count(),
            'HIGH': AttackLog.objects.filter(severity='HIGH').count(),
            'MEDIUM': AttackLog.objects.filter(severity='MEDIUM').count(),
            'LOW': AttackLog.objects.filter(severity='LOW').count(),
        }
    }
    
    return JsonResponse(stats)