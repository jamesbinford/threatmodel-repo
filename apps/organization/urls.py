from django.urls import path
from . import views

app_name = 'organization'

urlpatterns = [
    path('', views.BusinessUnitListView.as_view(), name='list'),
    path('<slug:slug>/', views.BusinessUnitDetailView.as_view(), name='detail'),
]
