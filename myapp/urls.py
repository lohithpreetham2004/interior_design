from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    path('',views.home,name='home'),
    path('login',views.loginpage,name='login'),
    path('register',views.register,name='register'),
    path('aboutus',views.aboutus,name='aboutus')
]