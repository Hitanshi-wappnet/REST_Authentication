from django.db import models
from django.contrib.auth.models import User


# This is the Model of ForgetPassword.
class ForgetPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
