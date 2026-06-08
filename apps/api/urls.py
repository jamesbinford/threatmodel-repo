from django.urls import path

from .views import InternalAPIStatusView, InternalReferenceView, InternalThreatModelDetailView


app_name = 'api'

urlpatterns = [
    path('', InternalAPIStatusView.as_view(), name='status'),
    path('reference/', InternalReferenceView.as_view(), name='reference'),
    path('threat-models/<slug:slug>/', InternalThreatModelDetailView.as_view(), name='threat-model-detail'),
]
