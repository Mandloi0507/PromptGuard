from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing, name='landing'),
    path('analyser/', views.analyser, name='analyser'),
    path('firewall/', views.firewall, name='firewall'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard/export/', views.export_logs, name='export-logs'),
]