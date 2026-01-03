from django.contrib import admin
from django.urls import path, include
from monitoring import views as monitor_views
from django.views.generic import RedirectView

urlpatterns = [
    path('', RedirectView.as_view(url='/vulnerable/login/', permanent=False)),
    path('admin/', admin.site.urls),
    path('vulnerable/', include('vulnerable.urls')),
    path('patched/', include('patched.urls')),
    path('monitoring/', monitor_views.log_viewer, name='monitoring'),
    path('monitoring/<str:filter_path>/', monitor_views.log_viewer, name='monitoring_filtered'),
    
    # Admin action endpoints
    path('monitoring/action/block/<int:log_id>/', monitor_views.block_ip_action, name='block_ip'),
    path('monitoring/action/unblock/<int:blocked_ip_id>/', monitor_views.unblock_ip_action, name='unblock_ip'),
    path('monitoring/action/revoke/<int:log_id>/', monitor_views.revoke_session_action, name='revoke_session'),
    path('monitoring/action/resolve/<int:log_id>/', monitor_views.resolve_log_action, name='resolve_log'),
    path('monitoring/export/', monitor_views.export_logs, name='export_logs'),
    path('monitoring/stats/', monitor_views.dashboard_stats, name='dashboard_stats'),
]