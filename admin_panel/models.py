from django.db import models
from django.conf import settings

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    profile_image = models.ImageField(upload_to='profile_pics/', default='src/images/user.png')
    birth_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

class ChildRecord(models.Model):
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
    ]

    WEIGHT_STATUS_CHOICES = [
        ('UW', 'Underweight'),
        ('ST', 'Stunted'),
        ('N', 'Normal'),
        ('SEVUW', 'Severely Underweight'),
        ('MW', 'Moderately Well'),
    ]

    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50)
    gender = models.CharField(max_length=6, choices=GENDER_CHOICES)
    date_entered = models.DateField()
    birthday = models.DateField()
    age_in_months = models.PositiveIntegerField()
    weight = models.DecimalField(max_digits=5, decimal_places=2)
    height = models.DecimalField(max_digits=5, decimal_places=2)
    weight_for_age_status = models.CharField(max_length=5, choices=WEIGHT_STATUS_CHOICES)
    height_for_age_status = models.CharField(max_length=5, choices=WEIGHT_STATUS_CHOICES)
    weight_for_lt_ht_status = models.CharField(max_length=5, choices=WEIGHT_STATUS_CHOICES)
    child_image = models.ImageField(upload_to='child_images/', blank=True, null=True)
    recommandations=models.TextField(blank=True,null=True)

    def __str__(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"

class MaternalRecord(models.Model):
    STATUS_CHOICES = [
        ('Pregnant', 'Pregnant'),
        ('Lactating', 'Lactating'),
    ]

    NUTRITIONAL_STATUS_CHOICES = [
        ('Normal', 'Normal'),
        ('Overweight', 'Overweight'),
        ('Underweight', 'Underweight'),
    ]

    FOUR_PS_MEMBER_CHOICES = [
        ('Yes', 'Yes'),
        ('No', 'No'),
    ]

    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    date_entered = models.DateTimeField(auto_now_add=True)
    birthday = models.DateField()
    age = models.PositiveIntegerField()
    muac = models.CharField(max_length=50)
    nutritional_status = models.CharField(max_length=20, choices=NUTRITIONAL_STATUS_CHOICES)
    four_ps_member = models.CharField(max_length=3, choices=FOUR_PS_MEMBER_CHOICES)
    image = models.ImageField(upload_to='maternal_records/', blank=True, null=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
