from django.urls import path
from .views import login_view, register, forgot_pass, reset_pass, admin_dashboard, superadmin_dashboard

from . import views
urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),

    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('superadmin-dashboard/', superadmin_dashboard, name='superadmin_dashboard'),
    
    
    
    # for password reset 
    path('forgotPassword/', views.forgotPassword, name='forgotpassword'),
    path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
    path('resetPassword/', views.resetPassword, name='resetpassword'),
]
