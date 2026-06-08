from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.organization.models import BusinessUnit
from .models import InternalAPIClient


class InternalAPIFoundationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_internal_api_namespace_is_routed(self):
        self.assertEqual(reverse('api:status'), '/api/internal/v1/')

    def test_internal_api_rejects_unauthenticated_requests(self):
        response = self.client.get(reverse('api:status'))

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class InternalAPIClientTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')
        cls.parent_bu = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.child_bu = BusinessUnit.objects.create(name='Payment APIs', slug='payment-apis', parent=cls.parent_bu)
        cls.other_bu = BusinessUnit.objects.create(name='Lending', slug='lending')

    def test_active_client_can_be_resolved_from_entra_claims(self):
        client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
        )

        resolved = InternalAPIClient.active_for_claims(app_id='app-123', object_id='object-123')

        self.assertEqual(resolved, client)
        self.assertTrue(resolved.is_usable)

    def test_inactive_client_is_not_resolved(self):
        InternalAPIClient.objects.create(
            name='Disabled Client',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
            is_active=False,
        )

        resolved = InternalAPIClient.active_for_claims(app_id='app-123', object_id='object-123')

        self.assertIsNone(resolved)

    def test_expired_client_is_not_resolved(self):
        InternalAPIClient.objects.create(
            name='Expired Client',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
            expires_at=timezone.now() - timedelta(days=1),
        )

        resolved = InternalAPIClient.active_for_claims(app_id='app-123', object_id='object-123')

        self.assertIsNone(resolved)

    def test_business_unit_scope_allows_descendants_only(self):
        client = InternalAPIClient.objects.create(
            name='Payments Client',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
            business_unit_scope=self.parent_bu,
        )

        self.assertTrue(client.business_unit_allowed(self.parent_bu))
        self.assertTrue(client.business_unit_allowed(self.child_bu))
        self.assertFalse(client.business_unit_allowed(self.other_bu))

    def test_mark_used_updates_last_used_timestamp(self):
        client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
        )

        client.mark_used()

        self.assertIsNotNone(client.last_used_at)
