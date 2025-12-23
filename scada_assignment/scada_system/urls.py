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
]