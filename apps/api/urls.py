from django.urls import path

from .views import InternalAPIStatusView, InternalReferenceView, InternalThreatModelDetailView, InternalThreatModelSubmissionView


app_name = 'api'

urlpatterns = [
    path('', InternalAPIStatusView.as_view(), name='status'),
    path('reference/', InternalReferenceView.as_view(), name='reference'),
    path('threat-models/', InternalThreatModelSubmissionView.as_view(), name='threat-model-submit'),
    path('threat-models/<slug:slug>/', InternalThreatModelDetailView.as_view(), name='threat-model-detail'),
]
