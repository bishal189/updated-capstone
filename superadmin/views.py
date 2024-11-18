from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from users.models import CustomUser
from datetime import timedelta
from django.utils.timezone import now

@login_required
def sa_account(request):
    return render(request, 'superadmin/sa-account.html')

@login_required
def sa_activitylog(request):
    return render(request, 'superadmin/sa-activitylog.html')

@login_required
def sa_index(request):
    return render(request, 'superadmin/sa-index.html')

@login_required
def sa_dashboard(request):
    users = CustomUser.objects.filter(account_type='admin').count() or 0
    active_admins = CustomUser.objects.filter(
        account_type='admin', last_login__gte=now() - timedelta(hours=24)
    ).count() or 0
    server_uptime_percentage = 98

    context = {
        'total_admins': users,
        'active_admins': active_admins,
        'server_uptime': server_uptime_percentage,
    }
    return render(request, 'superadmin/sa-dashboard.html', context)

@login_required
def sa_logout(request):
    return render(request, 'superadmin/sa-logout.html')

@login_required
def sa_reports(request):
    return render(request, 'superadmin/sa-reports.html')

@login_required
def sa_usermanagement(request):
    # Filter by 'admin' in account_type
    users = CustomUser.objects.filter(account_type='admin')
    return render(request, 'superadmin/sa-usermanagement.html', {'users': users})

@login_required
def sa_logout(request):
    logout(request)
    return redirect('login')
