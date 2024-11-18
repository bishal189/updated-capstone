from django.urls import path
from . import views

urlpatterns = [
    path('account/', views.sa_account, name='superadmin_account'),
    path('activity-log/', views.sa_activitylog, name='superadmin_activitylog'),
    path('index/', views.sa_index, name='superadmin_index'),
    path('dashboard/', views.sa_dashboard, name='superadmin_dashboard'),
    path('logout/', views.sa_logout, name='superadmin_logout'),
    path('reports/', views.sa_reports, name='superadmin_reports'),
    path('user-management/', views.sa_usermanagement, name='superadmin_usermanagement'),
    
]
