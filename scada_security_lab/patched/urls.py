from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.patched_login, name='patched_login'),
    path('dashboard/', views.patched_dashboard, name='patched_dashboard'),
    path('upload/', views.patched_upload, name='patched_upload'),
    path('report/', views.patched_report, name='patched_report'),
    path('ssrf/', views.patched_ssrf, name='patched_ssrf'),
    path('diagnostics/', views.patched_deserialize, name='patched_deserialize'),
    path('maintenance/', views.patched_maintenance_interface, name='patched_maintenance_interface'),
    path('assign/<int:device_id>/', views.patched_assign_technician, name='patched_assign_technician'),
    path('toggle/<int:device_id>/', views.patched_toggle_status, name='patched_toggle_status'),
]