from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class InternalAPIFoundationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_internal_api_namespace_is_routed(self):
        self.assertEqual(reverse('api:status'), '/api/internal/v1/')

    def test_internal_api_rejects_unauthenticated_requests(self):
        response = self.client.get(reverse('api:status'))

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
