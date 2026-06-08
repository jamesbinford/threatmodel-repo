from datetime import timedelta

import jwt
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from rest_framework import status
from rest_framework.test import APIClient

from apps.organization.models import BusinessUnit
from .models import InternalAPIClient


def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


class InternalAPIFoundationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_internal_api_namespace_is_routed(self):
        self.assertEqual(reverse('api:status'), '/api/internal/v1/')

    def test_internal_api_rejects_unauthenticated_requests(self):
        response = self.client.get(reverse('api:status'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


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


class EntraJWTAuthenticationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')

    def setUp(self):
        self.client = APIClient()
        self.private_key, self.public_key = rsa_key_pair()
        self.api_client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
        )

    def token(self, **overrides):
        now = timezone.now()
        claims = {
            'iss': 'https://login.microsoftonline.com/tenant-123/v2.0',
            'aud': 'api://threatmodel',
            'tid': 'tenant-123',
            'appid': 'app-123',
            'oid': 'object-123',
            'roles': ['ThreatModel.Submit'],
            'iat': int(now.timestamp()),
            'nbf': int(now.timestamp()),
            'exp': int((now + timedelta(minutes=10)).timestamp()),
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm='RS256')

    def auth_settings(self):
        return override_settings(
            ENTRA_TENANT_ID='tenant-123',
            ENTRA_ISSUER='https://login.microsoftonline.com/tenant-123/v2.0',
            ENTRA_AUDIENCE='api://threatmodel',
            ENTRA_REQUIRED_ROLES=['ThreatModel.Submit', 'ThreatModel.Admin'],
            ENTRA_TEST_PUBLIC_KEY=self.public_key,
        )

    def get_with_token(self, token):
        return self.client.get(reverse('api:status'), HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_valid_entra_token_authenticates_mapped_client(self):
        with self.auth_settings():
            response = self.get_with_token(self.token())

        self.api_client.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {'status': 'ok', 'version': 'v1'})
        self.assertIsNotNone(self.api_client.last_used_at)

    def test_wrong_audience_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token(self.token(aud='api://other-api'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrong_issuer_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token(self.token(iss='https://login.microsoftonline.com/other/v2.0'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrong_tenant_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token(self.token(tid='other-tenant'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_malformed_token_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token('not-a-jwt')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_expired_token_is_rejected(self):
        expired = int((timezone.now() - timedelta(minutes=1)).timestamp())

        with self.auth_settings():
            response = self.get_with_token(self.token(exp=expired))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_missing_required_role_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token(self.token(roles=['ThreatModel.Read']))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_invalid_signature_is_rejected(self):
        other_private_key, _public_key = rsa_key_pair()
        now = timezone.now()
        token = jwt.encode(
            {
                'iss': 'https://login.microsoftonline.com/tenant-123/v2.0',
                'aud': 'api://threatmodel',
                'tid': 'tenant-123',
                'appid': 'app-123',
                'oid': 'object-123',
                'roles': ['ThreatModel.Submit'],
                'exp': int((now + timedelta(minutes=10)).timestamp()),
            },
            other_private_key,
            algorithm='RS256',
        )

        with self.auth_settings():
            response = self.get_with_token(token)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unknown_client_is_rejected(self):
        with self.auth_settings():
            response = self.get_with_token(self.token(appid='unknown-app', oid='unknown-object'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
