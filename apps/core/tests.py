from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.mitre.models import Tactic, Technique
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import ThreatModel
from threatmodel.settings.env import env_bool


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


class SettingsEnvTests(TestCase):
    def test_env_bool_uses_default_when_value_is_missing(self):
        self.assertTrue(env_bool({}, 'MISSING', default=True))
        self.assertFalse(env_bool({}, 'MISSING', default=False))

    def test_env_bool_accepts_common_truthy_values(self):
        for value in ['1', 'true', 'TRUE', 'yes', 'on']:
            with self.subTest(value=value):
                self.assertTrue(env_bool({'FLAG': value}, 'FLAG'))

    def test_env_bool_treats_other_values_as_false(self):
        for value in ['0', 'false', 'no', 'off', '']:
            with self.subTest(value=value):
                self.assertFalse(env_bool({'FLAG': value}, 'FLAG', default=True))
