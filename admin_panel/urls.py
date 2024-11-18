# admin_panel/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('events/', views.admin_events, name='admin_events'),
    path('profile/', views.admin_profile, name='admin_profile'),
    path('program-management/', views.admin_program_management, name='admin_program_management'),
    path('child-record/', views.admin_child_record, name='admin_child_record'),
    path('maternal-record/', views.admin_maternal_record, name='admin_maternal_record'),
    path('reports/', views.admin_reports, name='admin_reports'),
    path('logout/', views.admin_logout, name='admin_logout'),
    path('recommadations/<int:id>/', views.recommadations, name='recommadations'),
    path('delete_record/<int:id>/', views.delete_record, name='delete_record'),

]
