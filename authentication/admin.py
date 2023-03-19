from django.contrib import admin
from authentication.models import ForgetPassword


# Registation of Forget Password Model
@admin.register(ForgetPassword)
class ForgetPasswordAdmin(admin.ModelAdmin):
    fields = ["user", "otp"]
