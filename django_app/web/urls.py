from django.urls import path
from . import views

urlpatterns = [
    path('', views.analyser, name='analyser'),
    path('firewall/', views.firewall, name='firewall'),
    path('dashboard/', views.dashboard, name='dashboard'),
]