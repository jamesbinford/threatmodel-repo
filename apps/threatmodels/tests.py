from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.organization.models import BusinessUnit
from .models import Diagram, Finding, ThreatModel
from .policies import can_edit_threat_model, can_view_threat_model


class ThreatModelPolicyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.other_user = User.objects.create_user(username='other', password='pass12345')
        cls.staff_user = User.objects.create_user(
            username='staff',
            password='pass12345',
            is_staff=True,
        )
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            owner=cls.owner,
        )

    def test_authenticated_users_can_view_threat_models(self):
        self.assertTrue(can_view_threat_model(self.owner, self.threat_model))
        self.assertTrue(can_view_threat_model(self.other_user, self.threat_model))

    def test_only_owner_or_staff_can_edit_threat_model(self):
        self.assertTrue(can_edit_threat_model(self.owner, self.threat_model))
        self.assertTrue(can_edit_threat_model(self.staff_user, self.threat_model))
        self.assertFalse(can_edit_threat_model(self.other_user, self.threat_model))


class ThreatModelAuthorizationViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.other_user = User.objects.create_user(username='other', password='pass12345')
        cls.staff_user = User.objects.create_user(
            username='staff',
            password='pass12345',
            is_staff=True,
        )
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            owner=cls.owner,
        )
        cls.other_threat_model = ThreatModel.objects.create(
            title='Lending Platform',
            slug='lending-platform',
            business_unit=cls.business_unit,
            description='Lending platform threat model.',
            owner=cls.other_user,
        )
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            threat_id='TM-001-F01',
            scenario='An attacker abuses weak authorization.',
            threat_object='Payment API',
            stride_category='E',
            inherent_risk=4,
            owner='API Security Team',
        )
        cls.other_finding = Finding.objects.create(
            threat_model=cls.other_threat_model,
            threat_id='TM-002-F01',
            scenario='An attacker exfiltrates data.',
            threat_object='Loan API',
            stride_category='I',
            inherent_risk=4,
            owner='Platform Team',
        )
        cls.diagram = Diagram.objects.create(
            threat_model=cls.threat_model,
            title='Architecture',
            file='diagrams/architecture.png',
        )

    def test_owner_can_edit_threat_model_and_child_objects(self):
        self.client.force_login(self.owner)
        urls = [
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_add', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.finding.pk}),
            reverse('threatmodels:diagram_upload', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:diagram_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
            reverse('threatmodels:diagram_delete', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 200)

    def test_staff_can_edit_threat_model(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}))

        self.assertEqual(response.status_code, 200)

    def test_non_owner_cannot_edit_threat_model_or_child_objects(self):
        self.client.force_login(self.other_user)
        urls = [
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_add', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.finding.pk}),
            reverse('threatmodels:diagram_upload', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:diagram_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
            reverse('threatmodels:diagram_delete', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 403)

    def test_child_object_permission_uses_actual_parent_not_url_slug(self):
        self.client.force_login(self.owner)
        url = reverse(
            'threatmodels:finding_edit',
            kwargs={'slug': self.threat_model.slug, 'pk': self.other_finding.pk},
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 403)
