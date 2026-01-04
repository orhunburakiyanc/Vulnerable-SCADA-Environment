from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.vulnerable_login, name='vulnerable_login'),
    path('logout/', views.vulnerable_logout, name='vulnerable_logout'),
    path('dashboard/', views.vulnerable_dashboard, name='vulnerable_dashboard'),
    path('upload/', views.vulnerable_upload, name='vulnerable_upload'), 
    path('report/', views.vulnerable_report, name='vulnerable_report'),
    path('toggle/<int:device_id>/', views.toggle_status, name='toggle_status'),
    path('deserialize/', views.vulnerable_deserialize, name='vulnerable_deserialize'),
    path('ssrf/', views.vulnerable_ssrf, name='vulnerable_ssrf'),
    path('maintenance/', views.maintenance_interface, name='maintenance_interface'),
    path('assign/<int:device_id>/', views.assign_technician, name='assign_technician'),
]