from django.urls import path
from . import views

urlpatterns = [
    path('analyze', views.analyze, name='analyze'),
    path('analyze-file', views.analyze_file, name='analyze-file'),
    path('analyze-image', views.analyze_image, name='analyze-image'),
    path('firewall', views.firewall_view, name='firewall'),
    path('firewall-file', views.firewall_file, name='firewall-file'),
    path('firewall-image', views.firewall_image, name='firewall-image'),
]
