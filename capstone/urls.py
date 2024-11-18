from django.contrib import admin
from django.shortcuts import redirect
from django.urls import path, include
from users import views as user_views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', lambda request: redirect('login'), name='home'),  # Redirect to login
    path('admin/', admin.site.urls),  # Django admin
    path('users/', include('users.urls')),  # Include user app URLs
    path('admin_panel/', include('admin_panel.urls')),  # Include admin panel URLs
    path('superadmin/', include('superadmin.urls')),  # Include all superadmin URLs
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
