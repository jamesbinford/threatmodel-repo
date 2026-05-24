from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.threatmodels.models import ThreatModel
from .models import BusinessUnit


class BusinessUnitViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='analyst', password='pass12345')
        cls.parent = BusinessUnit.objects.create(
            name='Retail Banking',
            slug='retail-banking',
            description='Retail banking products.',
        )
        cls.child = BusinessUnit.objects.create(
            name='Digital Banking',
            slug='digital-banking',
            parent=cls.parent,
        )
        cls.threat_model = ThreatModel.objects.create(
            title='Mobile Banking',
            slug='mobile-banking',
            business_unit=cls.child,
            description='Mobile banking threat model.',
            owner=cls.user,
            status='published',
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_business_unit_list_contains_tree_nodes(self):
        response = self.client.get(reverse('organization:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['business_units']), [self.parent, self.child])

    def test_business_unit_detail_includes_children_ancestors_and_models(self):
        response = self.client.get(reverse('organization:detail', kwargs={'slug': self.child.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['ancestors']), [self.parent])
        self.assertEqual(list(response.context['children']), [])
        self.assertEqual(list(response.context['threat_models']), [self.threat_model])

    def test_parent_business_unit_detail_includes_children(self):
        response = self.client.get(reverse('organization:detail', kwargs={'slug': self.parent.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['children']), [self.child])
        self.assertEqual(list(response.context['threat_models']), [])
