from django.urls import path
from user.views import *

# from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('validate_phone/', ValidatePhoneSendOTP.as_view(), name='validate_phone'),
    path('validate_otp/', ValidateOTP.as_view(), name='validate_otp'),
    path('register/', Register.as_view(), name='register')
    ]