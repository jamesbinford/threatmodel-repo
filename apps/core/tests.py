import importlib
import os
import sys
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.mitre.models import Tactic, Technique
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import ThreatModel


class ProductionSecuritySettingsTests(SimpleTestCase):
    def import_production_settings(self, env):
        sys.modules.pop('threatmodel.settings.production', None)
        with patch.dict(os.environ, env, clear=False):
            return importlib.import_module('threatmodel.settings.production')

    def tearDown(self):
        sys.modules.pop('threatmodel.settings.production', None)
        super().tearDown()

    def test_https_security_settings_default_to_enabled(self):
        production_settings = self.import_production_settings({
            'SECRET_KEY': 'test-secret-key',
            'ALLOWED_HOSTS': 'example.com',
        })

        self.assertTrue(production_settings.SECURE_SSL_REDIRECT)
        self.assertTrue(production_settings.SESSION_COOKIE_SECURE)
        self.assertTrue(production_settings.CSRF_COOKIE_SECURE)
        self.assertEqual(production_settings.SECURE_HSTS_SECONDS, 31536000)
        self.assertEqual(production_settings.SECURE_PROXY_SSL_HEADER, ('HTTP_X_FORWARDED_PROTO', 'https'))

    def test_https_security_settings_can_be_disabled_for_terminating_proxy_exceptions(self):
        production_settings = self.import_production_settings({
            'SECRET_KEY': 'test-secret-key',
            'ALLOWED_HOSTS': 'example.com',
            'SECURE_SSL_REDIRECT': 'false',
            'SESSION_COOKIE_SECURE': 'false',
            'CSRF_COOKIE_SECURE': 'false',
            'USE_X_FORWARDED_PROTO': 'false',
        })

        self.assertFalse(production_settings.SECURE_SSL_REDIRECT)
        self.assertFalse(production_settings.SESSION_COOKIE_SECURE)
        self.assertFalse(production_settings.CSRF_COOKIE_SECURE)
        self.assertFalse(hasattr(production_settings, 'SECURE_PROXY_SSL_HEADER'))


class AuthenticatedReadViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='analyst', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(
            name='Digital Banking',
            slug='digital-banking',
        )
        cls.threat_model = ThreatModel.objects.create(
            title='Mobile Banking App',
            slug='mobile-banking-app',
            business_unit=cls.business_unit,
            description='Mobile banking threat model.',
            overall_risk=4,
            status='published',
            owner=cls.user,
        )
        cls.tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='The adversary is trying to get into your network.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.technique = Technique.objects.create(
            technique_id='T1566',
            name='Phishing',
            description='Adversaries may send phishing messages.',
            framework='attack',
            tactic=cls.tactic,
            url='https://attack.mitre.org/techniques/T1566/',
        )

    def protected_urls(self):
        return [
            reverse('home'),
            reverse('threatmodels:list'),
            reverse('threatmodels:detail', kwargs={'slug': self.threat_model.slug}),
            reverse('organization:list'),
            reverse('organization:detail', kwargs={'slug': self.business_unit.slug}),
            reverse('mitre:list'),
            reverse('mitre:tactic_detail', kwargs={'tactic_id': self.tactic.tactic_id}),
            reverse('mitre:technique_detail', kwargs={'technique_id': self.technique.technique_id}),
            reverse('reports:dashboard'),
            reverse('reports:tag_frequency'),
            reverse('reports:dashboard_pdf'),
        ]

    def test_anonymous_users_are_redirected_to_login(self):
        for url in self.protected_urls():
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 302)
                self.assertTrue(response['Location'].startswith(f'{reverse("accounts:login")}?next='))

    def test_authenticated_users_can_access_sensitive_read_views(self):
        self.client.force_login(self.user)
        urls = [
            reverse('home'),
            reverse('threatmodels:list'),
            reverse('threatmodels:detail', kwargs={'slug': self.threat_model.slug}),
            reverse('organization:list'),
            reverse('organization:detail', kwargs={'slug': self.business_unit.slug}),
            reverse('mitre:list'),
            reverse('mitre:tactic_detail', kwargs={'tactic_id': self.tactic.tactic_id}),
            reverse('mitre:technique_detail', kwargs={'technique_id': self.technique.technique_id}),
            reverse('reports:dashboard'),
            reverse('reports:tag_frequency'),
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 200)
