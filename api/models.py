from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser

# here is two model create user in user model there many field admin, provider and seeker

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('solution_provider', 'Solution Provider'),
        ('solution_seeker', 'Solution Seeker'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

# profile model 

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)


