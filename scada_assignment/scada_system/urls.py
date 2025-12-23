from django.contrib import admin
from django.urls import path, include
from monitoring import views as monitor_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('vulnerable/', include('vulnerable.urls')),
    path('patched/', include('patched.urls')),
    path('monitoring/', monitor_views.log_viewer),
]