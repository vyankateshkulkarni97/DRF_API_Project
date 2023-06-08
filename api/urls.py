from django.urls import path
from .views import (
    UserRegisterView,
    UserLoginView,
    UserChangePasswordView,
    UserForgotPasswordView,
    UserProfileView,
)

urlpatterns = [

    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('change-password/', UserChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', UserForgotPasswordView.as_view(), name='forgot_password'),
    path('profile/', UserProfileView.as_view(), name='profile'),
]
