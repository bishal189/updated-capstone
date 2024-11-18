# admin_panel/views.py
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from users.models import CustomUser
from .models import ChildRecord,MaternalRecord
from django.core.files.storage import FileSystemStorage
from datetime import datetime

@login_required
def admin_dashboard(request):
    return render(request, 'admin_panel/index.html')

@login_required
def admin_events(request):
    return render(request, 'admin_panel/events.html')

@login_required
def admin_profile(request):
    user = request.user

    if request.method == 'POST':
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.username = request.POST.get('username', '')
        user.email = request.POST.get('email', '')
        user.birth_date = request.POST.get('birth_date', '')
        user.gender = request.POST.get('gender', '')
        user.contact_number = request.POST.get('contact_number', '')
        
        user.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('admin_profile')

    return render(request, 'admin_panel/profile.html', {'user': user})

@login_required
def admin_program_management(request):
    return render(request, 'admin_panel/progmanagement.html')

import requests
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import ChildRecord

# Hugging Face API settings
HF_API_URL = "https://api-inference.huggingface.co/models/gpt2"
HF_API_TOKEN = "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" 

def generate_recommendations(status, weight, height, age):
    """
    Function to generate recommendations using Hugging Face API.
    """
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    prompt = (
        f"A child is {status}, which means their weight is lower than average for their age. "
        f"The child's weight is {weight} kg, height is {height} cm, and they are {age} months old. "
        f"Please recommend specific actions, foods, or medicines that could help improve the child's health. "
        f"Provide nutritional advice, suggest foods to gain weight, or possible medical checkups or treatments."
        f'provide food details to be takes based on the age and weight'
    )
    response = requests.post(HF_API_URL, headers=headers, json={"inputs": prompt})
    print(response)

    if response.status_code == 200:
        data = response.json()
        print(data)
        return data[0]["generated_text"]
    else:
        return "Unable to generate recommendations at the moment. Please try again later."

@login_required
def admin_child_record(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        middle_name = request.POST.get('middle_name', '')
        last_name = request.POST.get('last_name')
        gender = request.POST.get('gender')
        date_entered = request.POST.get('date_entered')
        birthday = request.POST.get('birthday')
        age_in_months = int(request.POST.get('age_in_months', 0))  # Ensure numeric type
        weight = float(request.POST.get('weight', 0))  # Ensure numeric type
        height = float(request.POST.get('height', 0))  # Ensure numeric type
        weight_for_age_status = 'underweight'
        height_for_age_status = 12
        weight_for_lt_ht_status = request.POST.get('weight_for_lt_ht_status')
        child_image = request.FILES.get('child_image')

        # Save the child record
        record = ChildRecord.objects.create(
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            gender=gender,
            date_entered=date_entered,
            birthday=birthday,
            age_in_months=age_in_months,
            weight=weight,
            height=height,
            weight_for_age_status=weight_for_age_status,
            height_for_age_status=height_for_age_status,
            weight_for_lt_ht_status=weight_for_lt_ht_status,
            child_image=child_image,
        )

        # Check if the child is underweight and generate recommendations
        if weight_for_age_status.lower() == 'underweight':
            recommendations = generate_recommendations(
                weight_for_age_status, weight, height, age_in_months
            )
            record.recommandations=recommendations
            record.save()
            print('data save')
            messages.success(
                request,
                f"Child record added successfully! AI Recommendation: {recommendations}",
            )
            print('hello world')
            context={
                'recommendations':recommendations
            }
            print('hello next')
            return redirect('admin_dashboard')

        else:
            messages.success(request, 'Child record added successfully!')
            
       
    # Retrieve all records
    records = ChildRecord.objects.all()
    return render(request, 'admin_panel/child_record.html', {'records': records})

def admin_maternal_record(request):
    if request.method == 'POST':
        try:
            first_name = request.POST.get('first_name')
            middle_name = request.POST.get('middle_name')
            last_name = request.POST.get('last_name')
            status = request.POST.get('status')
            birthday = request.POST.get('birthday')
            age = request.POST.get('age')
            muac = request.POST.get('muac')
            nutritional_status = request.POST.get('nutritional_status')
            four_ps_member = request.POST.get('four_ps_member')
            maternal_image = request.FILES.get('image')

            record = MaternalRecord.objects.create(
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                status=status,
                birthday=birthday,
                age=age,
                muac=muac,
                nutritional_status=nutritional_status,
                four_ps_member=four_ps_member
            )

            if maternal_image:
                record.image = maternal_image

            record.save()

            messages.success(request, 'Maternal record added successfully!')
            return redirect('admin_maternal_record')

        except Exception as e:
            messages.error(request, f"Error saving record: {str(e)}")
            print(f"Error saving record: {str(e)}")

    records = MaternalRecord.objects.all()
    return render(request, 'admin_panel/maternal_record.html', {'records': records})

@login_required
def admin_reports(request):
    return render(request, 'admin_panel/reports.html')

@login_required
def admin_logout(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login')





def recommadations(request,id):
    record=ChildRecord.objects.get(id=id)
    context={
        'record':record.recommandations
    }
    return render(request,'admin_panel/recommand.html',context)

def delete_record(request,id):
    record=ChildRecord.objects.get(id=id)
    record.delete()
    return redirect('admin_child_record')
    