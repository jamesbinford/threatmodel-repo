from django.urls import path
from . import views

app_name = 'mitre'

urlpatterns = [
    path('', views.TechniqueListView.as_view(), name='list'),
    path('tactic/<str:tactic_id>/', views.TacticDetailView.as_view(), name='tactic_detail'),
    path('<str:technique_id>/', views.TechniqueDetailView.as_view(), name='technique_detail'),
]
