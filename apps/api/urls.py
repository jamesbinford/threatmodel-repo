from django.urls import path

from .views import InternalAPIStatusView


app_name = 'api'

urlpatterns = [
    path('', InternalAPIStatusView.as_view(), name='status'),
]
