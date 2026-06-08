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
from apps.mitre.models import Tactic, Technique
from apps.threatmodels.models import Finding, TechnologyTag, ThreatModel
from .models import APISubmission, InternalAPIClient


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


class APISubmissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payments API',
            slug='payments-api',
            business_unit=cls.business_unit,
            description='Payments API threat model.',
            owner=cls.user,
        )
        cls.api_client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=cls.user,
        )

    def test_api_submission_records_metadata_without_payload(self):
        request = type('Request', (), {})()
        request.headers = {
            'X-Request-ID': 'request-123',
            'Idempotency-Key': 'idem-123',
        }
        request.path = '/api/internal/v1/threat-models/'
        request.method = 'POST'
        request.user = self.user
        request.internal_api_client = self.api_client
        request.META = {'REMOTE_ADDR': '10.0.0.5'}

        submission = APISubmission.record(request, status_code=201, threat_model=self.threat_model)

        self.assertEqual(submission.request_id, 'request-123')
        self.assertEqual(submission.idempotency_key, 'idem-123')
        self.assertEqual(submission.endpoint, '/api/internal/v1/threat-models/')
        self.assertEqual(submission.method, 'POST')
        self.assertEqual(submission.user, self.user)
        self.assertEqual(submission.api_client, self.api_client)
        self.assertEqual(submission.source_ip, '10.0.0.5')
        self.assertEqual(submission.status_code, 201)
        self.assertEqual(submission.threat_model, self.threat_model)
        self.assertFalse(hasattr(submission, 'payload'))


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


class InternalAPIReadbackTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')
        cls.parent_bu = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.child_bu = BusinessUnit.objects.create(name='Payment APIs', slug='payment-apis', parent=cls.parent_bu)
        cls.other_bu = BusinessUnit.objects.create(name='Lending', slug='lending')
        cls.tag = TechnologyTag.objects.create(name='API', slug='api')
        cls.tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Initial access tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.technique = Technique.objects.create(
            technique_id='T1190',
            name='Exploit Public-Facing Application',
            description='Exploit technique.',
            framework='attack',
            tactic=cls.tactic,
            url='https://attack.mitre.org/techniques/T1190/',
        )
        cls.threat_model = ThreatModel.objects.create(
            external_id='service-catalog:payments-api',
            source_system='service-catalog',
            title='Payments API',
            slug='payments-api',
            business_unit=cls.child_bu,
            description='Payments API threat model.',
            overall_risk=4,
            owner=cls.user,
        )
        cls.threat_model.tags.add(cls.tag)
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            external_id='authz-001',
            threat_id='PAY-001',
            scenario='Broken authorization.',
            threat_object='Payments API',
            mitre_technique=cls.technique,
            stride_category='E',
            inherent_risk=4,
            owner='AppSec',
            status='open',
        )
        cls.other_threat_model = ThreatModel.objects.create(
            title='Lending API',
            slug='lending-api',
            business_unit=cls.other_bu,
            description='Lending API threat model.',
            owner=cls.user,
        )

    def setUp(self):
        self.client = APIClient()
        self.private_key, self.public_key = rsa_key_pair()
        self.api_client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
            business_unit_scope=self.parent_bu,
        )

    def token(self, **overrides):
        now = timezone.now()
        claims = {
            'iss': 'https://login.microsoftonline.com/tenant-123/v2.0',
            'aud': 'api://threatmodel',
            'tid': 'tenant-123',
            'appid': 'app-123',
            'oid': 'object-123',
            'roles': ['ThreatModel.Read'],
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
            ENTRA_REQUIRED_ROLES=['ThreatModel.Submit', 'ThreatModel.Read', 'ThreatModel.Admin'],
            ENTRA_TEST_PUBLIC_KEY=self.public_key,
        )

    def authorize(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token()}')

    def test_reference_endpoint_returns_filtered_lookup_values(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.get(reverse('api:reference'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn({'value': 4, 'label': 'High'}, data['risk'])
        self.assertIn('draft', data['threat_model_statuses'])
        self.assertIn('open', data['finding_statuses'])
        self.assertIn('E', data['stride_categories'])
        self.assertEqual(
            data['business_units'],
            [
                {'slug': 'payments', 'name': 'Payments'},
                {'slug': 'payment-apis', 'name': 'Payment APIs'},
            ],
        )
        self.assertEqual(data['tags'], ['API'])
        self.assertEqual(data['mitre_techniques'][0]['technique_id'], 'T1190')

    def test_threat_model_readback_returns_normalized_data(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.get(
                reverse('api:threat-model-detail', kwargs={'slug': self.threat_model.slug})
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['external_id'], 'service-catalog:payments-api')
        self.assertEqual(data['source_system'], 'service-catalog')
        self.assertEqual(data['business_unit'], 'payment-apis')
        self.assertEqual(data['computed_risk'], 4)
        self.assertEqual(data['tags'], ['API'])
        self.assertEqual(data['findings'][0]['external_id'], 'authz-001')
        self.assertEqual(data['findings'][0]['mitre_technique'], 'T1190')
        self.assertTrue(data['html_url'].endswith('/threatmodels/payments-api/'))

    def test_out_of_scope_threat_model_readback_is_rejected(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.get(
                reverse('api:threat-model-detail', kwargs={'slug': self.other_threat_model.slug})
            )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unknown_threat_model_readback_returns_not_found(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.get(
                reverse('api:threat-model-detail', kwargs={'slug': 'missing'})
            )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class InternalAPIThreatModelSubmissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')
        cls.parent_bu = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.child_bu = BusinessUnit.objects.create(name='Payment APIs', slug='payment-apis', parent=cls.parent_bu)
        cls.other_bu = BusinessUnit.objects.create(name='Lending', slug='lending')
        cls.tag = TechnologyTag.objects.create(name='API', slug='api')
        cls.tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Initial access tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.technique = Technique.objects.create(
            technique_id='T1190',
            name='Exploit Public-Facing Application',
            description='Exploit technique.',
            framework='attack',
            tactic=cls.tactic,
            url='https://attack.mitre.org/techniques/T1190/',
        )

    def setUp(self):
        self.client = APIClient()
        self.private_key, self.public_key = rsa_key_pair()
        self.api_client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
            business_unit_scope=self.parent_bu,
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
            ENTRA_REQUIRED_ROLES=['ThreatModel.Submit', 'ThreatModel.Read', 'ThreatModel.Admin'],
            ENTRA_TEST_PUBLIC_KEY=self.public_key,
        )

    def authorize(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token()}')

    def payload(self, **overrides):
        data = {
            'external_id': 'service-catalog:payments-api',
            'source_system': 'service-catalog',
            'title': 'Payments API',
            'business_unit': 'payment-apis',
            'description': 'Payments API threat model.',
            'status': 'draft',
            'overall_risk': 4,
            'tags': ['API'],
            'findings': [
                {
                    'external_id': 'authz-001',
                    'threat_id': 'PAY-001',
                    'scenario': 'Broken authorization exposes payment data.',
                    'threat_object': 'Payments API',
                    'stride_category': 'E',
                    'inherent_risk': 4,
                    'mitre_technique': 'T1190',
                    'owner': 'AppSec',
                    'status': 'open',
                }
            ],
        }
        data.update(overrides)
        return data

    def test_submit_threat_model_creates_model_and_nested_findings(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(reverse('api:threat-model-submit'), self.payload(), format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.json()
        threat_model = ThreatModel.objects.get(external_id='service-catalog:payments-api')
        self.assertEqual(data['slug'], 'payments-api')
        self.assertTrue(data['created'])
        self.assertEqual(data['finding_count'], 1)
        self.assertEqual(data['computed_risk'], 4)
        self.assertEqual(threat_model.owner, self.user)
        self.assertEqual(threat_model.tags.get(), self.tag)
        self.assertEqual(threat_model.findings.get().mitre_technique, self.technique)
        self.assertTrue(APISubmission.objects.filter(threat_model=threat_model, status_code=201).exists())

    def test_submit_threat_model_retries_update_by_external_id(self):
        self.authorize()
        with self.auth_settings():
            create_response = self.client.post(reverse('api:threat-model-submit'), self.payload(), format='json')
            update_response = self.client.post(
                reverse('api:threat-model-submit'),
                self.payload(title='Payments API Updated', overall_risk=5),
                format='json',
            )

        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertFalse(update_response.json()['created'])
        self.assertEqual(ThreatModel.objects.count(), 1)
        self.assertEqual(Finding.objects.count(), 1)
        threat_model = ThreatModel.objects.get()
        self.assertEqual(threat_model.title, 'Payments API Updated')
        self.assertEqual(threat_model.overall_risk, 5)

    def test_submit_threat_model_rejects_unknown_lookup_values(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:threat-model-submit'),
                self.payload(
                    business_unit='missing',
                    tags=['Missing'],
                    findings=[{
                        'external_id': 'authz-001',
                        'threat_id': 'PAY-001',
                        'scenario': 'Broken authorization.',
                        'threat_object': 'Payments API',
                        'stride_category': 'E',
                        'inherent_risk': 4,
                        'mitre_technique': 'T9999',
                        'owner': 'AppSec',
                    }],
                ),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('business_unit', response.json())
        self.assertIn('tags', response.json())
        self.assertIn('findings', response.json())

    def test_submit_threat_model_rejects_invalid_enum_values(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:threat-model-submit'),
                self.payload(status='invalid', findings=[{
                    'external_id': 'authz-001',
                    'threat_id': 'PAY-001',
                    'scenario': 'Broken authorization.',
                    'threat_object': 'Payments API',
                    'stride_category': 'X',
                    'inherent_risk': 9,
                    'owner': 'AppSec',
                }]),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('status', response.json())
        self.assertIn('findings', response.json())

    def test_submit_threat_model_rejects_out_of_scope_business_unit(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:threat-model-submit'),
                self.payload(business_unit='lending'),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class InternalAPIFindingSubmissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='service-account', password='pass12345')
        cls.other_user = User.objects.create_user(username='other-service', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Initial access tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.technique = Technique.objects.create(
            technique_id='T1190',
            name='Exploit Public-Facing Application',
            description='Exploit technique.',
            framework='attack',
            tactic=cls.tactic,
            url='https://attack.mitre.org/techniques/T1190/',
        )
        cls.threat_model = ThreatModel.objects.create(
            title='Payments API',
            slug='payments-api',
            business_unit=cls.business_unit,
            description='Payments API threat model.',
            owner=cls.user,
        )

    def setUp(self):
        self.client = APIClient()
        self.private_key, self.public_key = rsa_key_pair()
        self.api_client = InternalAPIClient.objects.create(
            name='Service Catalog',
            entra_app_id='app-123',
            entra_object_id='object-123',
            user=self.user,
        )
        self.other_api_client = InternalAPIClient.objects.create(
            name='Other Service',
            entra_app_id='app-456',
            entra_object_id='object-456',
            user=self.other_user,
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
            ENTRA_REQUIRED_ROLES=['ThreatModel.Submit', 'ThreatModel.Read', 'ThreatModel.Admin'],
            ENTRA_TEST_PUBLIC_KEY=self.public_key,
        )

    def authorize(self, **claims):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token(**claims)}')

    def finding_payload(self, **overrides):
        finding = {
            'external_id': 'authz-001',
            'threat_id': 'PAY-001',
            'scenario': 'Broken authorization exposes payment data.',
            'threat_object': 'Payments API',
            'stride_category': 'E',
            'inherent_risk': 4,
            'mitre_technique': 'T1190',
            'owner': 'AppSec',
            'status': 'open',
        }
        finding.update(overrides)
        return {'findings': [finding]}

    def test_finding_endpoint_creates_findings_for_authorized_caller(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': self.threat_model.slug}),
                self.finding_payload(),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['created'], 1)
        finding = self.threat_model.findings.get()
        self.assertEqual(finding.external_id, 'authz-001')
        self.assertEqual(finding.mitre_technique, self.technique)

    def test_finding_endpoint_updates_existing_external_id_without_duplicate(self):
        self.authorize()

        with self.auth_settings():
            create_response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': self.threat_model.slug}),
                self.finding_payload(),
                format='json',
            )
            update_response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': self.threat_model.slug}),
                self.finding_payload(status='in_progress', inherent_risk=5),
                format='json',
            )

        self.assertEqual(create_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.json()['updated'], 1)
        self.assertEqual(Finding.objects.count(), 1)
        finding = Finding.objects.get()
        self.assertEqual(finding.status, 'in_progress')
        self.assertEqual(finding.inherent_risk, 5)

    def test_finding_endpoint_rejects_unauthorized_caller(self):
        self.authorize(appid='app-456', oid='object-456')

        with self.auth_settings():
            response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': self.threat_model.slug}),
                self.finding_payload(),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Finding.objects.count(), 0)

    def test_finding_endpoint_returns_not_found_for_unknown_slug(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': 'missing'}),
                self.finding_payload(),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_finding_endpoint_returns_field_specific_validation_errors(self):
        self.authorize()

        with self.auth_settings():
            response = self.client.post(
                reverse('api:finding-submit', kwargs={'slug': self.threat_model.slug}),
                self.finding_payload(stride_category='X', mitre_technique='T9999'),
                format='json',
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('findings', response.json())
