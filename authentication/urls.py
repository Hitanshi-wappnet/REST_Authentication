from django.urls import path
from authentication import views

urlpatterns = [
    path('register/', views.UserRegisterView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('changepassword/', views.UserChangePasswordView.as_view(),
         name='changepassword'),
    path('changeprofile/', views.UserChangeProfileView.as_view(),
         name="changeprofile"),
    path('deleteprofile/', views.DeleteProfileView.as_view(),
         name="deleteprofile")
]
