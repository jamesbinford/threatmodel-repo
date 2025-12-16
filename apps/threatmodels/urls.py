from django.urls import path
from . import views

app_name = 'threatmodels'

urlpatterns = [
    path('', views.ThreatModelListView.as_view(), name='list'),
    path('create/', views.ThreatModelCreateView.as_view(), name='create'),
    path('<slug:slug>/', views.ThreatModelDetailView.as_view(), name='detail'),
    path('<slug:slug>/edit/', views.ThreatModelUpdateView.as_view(), name='edit'),
    path('<slug:slug>/findings/add/', views.FindingCreateView.as_view(), name='finding_add'),
    path('<slug:slug>/findings/<int:pk>/edit/', views.FindingUpdateView.as_view(), name='finding_edit'),
]
