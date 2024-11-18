# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class CustomUser(AbstractUser):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
    ]

    ACCOUNT_TYPE_CHOICES = [
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    ]

    first_name = models.CharField(max_length=30, blank=False)
    last_name = models.CharField(max_length=30, blank=False)
    gender = models.CharField(
        max_length=10,
        choices=GENDER_CHOICES,
        blank=False,
        null=False
    )
    contact_number = models.CharField(max_length=11, default='', blank=True)
    email = models.EmailField(unique=True)
    last_activity = models.DateTimeField(auto_now=True)
    account_type = models.CharField(
        max_length=10,
        choices=ACCOUNT_TYPE_CHOICES,
        default='admin',
        blank=False,
        null=False
    )

    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    def is_online(self):
        now = timezone.now()
        return self.last_activity >= now - timezone.timedelta(minutes=5)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
