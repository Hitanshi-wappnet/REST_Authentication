from django.urls import path
from authentication import views

# Define URL patterns for authentication views
urlpatterns = [
     # Register new user
     path('register/', views.UserRegisterView.as_view(), name='register'),

     # User login
     path('login/', views.UserLoginView.as_view(), name='login'),

     # Change user password
     path('changepassword/', views.UserChangePasswordView.as_view(),
          name='changepassword'),

     # Change user profile information
     path('changeprofile/', views.UserChangeProfileView.as_view(),
          name="changeprofile"),

     # Delete user profile
     path('deleteprofile/', views.DeleteProfileView.as_view(),
          name="deleteprofile"),

     # Forget user password
     path("forgetpassword/", views.UserForgetPasswordView.as_view(),
          name="forget-password"),

     # Verify user OTP
     path("verifyotp/", views.UserVerifyOtpView.as_view(), name="verifyotp"),

     # Reset user password
     path("resetpassword/", views.UserResetPasswordView.as_view(),
          name="resetpassword"),
]
