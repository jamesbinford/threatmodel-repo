import json
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.mitre.models import Tactic, Technique
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import Finding, TechnologyTag, ThreatModel


class ReportViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='analyst', password='pass12345')
        cls.parent_bu = BusinessUnit.objects.create(name='Retail Banking', slug='retail-banking')
        cls.child_bu = BusinessUnit.objects.create(
            name='Digital Banking',
            slug='digital-banking',
            parent=cls.parent_bu,
        )
        cls.tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Initial access tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.technique = Technique.objects.create(
            technique_id='T1566',
            name='Phishing',
            description='Phishing technique.',
            framework='attack',
            tactic=cls.tactic,
            url='https://attack.mitre.org/techniques/T1566/',
        )
        cls.mobile_tag = TechnologyTag.objects.create(name='Mobile', slug='mobile')
        cls.api_tag = TechnologyTag.objects.create(name='API', slug='api')
        cls.published_tm = ThreatModel.objects.create(
            title='Mobile Banking',
            slug='mobile-banking',
            business_unit=cls.child_bu,
            description='Mobile banking threat model.',
            overall_risk=4,
            status='published',
            owner=cls.user,
        )
        cls.published_tm.tags.add(cls.mobile_tag, cls.api_tag)
        cls.draft_tm = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.parent_bu,
            description='Payment gateway threat model.',
            overall_risk=2,
            status='draft',
            owner=cls.user,
        )
        cls.draft_tm.tags.add(cls.api_tag)
        Finding.objects.create(
            threat_model=cls.published_tm,
            threat_id='TM-001-F01',
            scenario='Phishing attack.',
            threat_object='User credentials',
            mitre_technique=cls.technique,
            stride_category='S',
            inherent_risk=4,
            owner='Mobile Security Team',
        )
        Finding.objects.create(
            threat_model=cls.published_tm,
            threat_id='TM-001-F02',
            scenario='Logging sensitive data.',
            threat_object='Application logs',
            stride_category='I',
            inherent_risk=3,
            residual_risk=1,
            owner='Platform Team',
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_dashboard_context_aggregates_core_metrics(self):
        response = self.client.get(reverse('reports:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['total_threat_models'], 2)
        self.assertEqual(response.context['total_findings'], 2)
        self.assertEqual(response.context['published_count'], 1)
        self.assertEqual(len(response.context['high_risk_findings']), 1)
        self.assertEqual(response.context['top_techniques'][0], self.technique)

    def test_dashboard_context_includes_computed_risk_recommendations(self):
        self.published_tm.overall_risk = 2
        self.published_tm.save()

        response = self.client.get(reverse('reports:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            {'risk': 4, 'label': 'High', 'count': 1},
            response.context['computed_risk_distribution'],
        )
        self.assertEqual(response.context['risk_discrepancy_count'], 1)
        self.assertEqual(list(response.context['risk_discrepancies']), [self.published_tm])

    def test_dashboard_serializes_chart_data(self):
        response = self.client.get(reverse('reports:dashboard'))

        risk_distribution = json.loads(response.context['risk_distribution_json'])
        computed_risk_distribution = json.loads(response.context['computed_risk_distribution_json'])
        stride_distribution = json.loads(response.context['stride_distribution_json'])
        bu_risk = json.loads(response.context['bu_risk_json'])
        trend_labels = json.loads(response.context['trend_labels_json'])
        trend_datasets = json.loads(response.context['trend_datasets_json'])

        self.assertIn({'overall_risk': 4, 'count': 1}, risk_distribution)
        self.assertIn({'risk': 4, 'label': 'High', 'count': 1}, computed_risk_distribution)
        self.assertIn({'stride_category': 'S', 'count': 1}, stride_distribution)
        self.assertTrue(any(item['name'] == 'Digital Banking' for item in bu_risk))
        self.assertTrue(trend_labels)
        self.assertTrue(any(dataset['label'] == 'Retail Banking' for dataset in trend_datasets))

    def test_tag_frequency_report_defaults_invalid_period_to_30_days(self):
        response = self.client.get(reverse('reports:tag_frequency'), {'period': 'invalid'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['period'], 30)
        self.assertEqual(response.context['total_tags'], 2)
        self.assertEqual(response.context['tags_used_in_period'], 2)
        self.assertEqual(response.context['threat_models_in_period'], 2)
        self.assertEqual(response.context['tagged_threat_models'], 2)

    def test_tag_frequency_report_defaults_unsupported_numeric_period_to_30_days(self):
        response = self.client.get(reverse('reports:tag_frequency'), {'period': '7'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['period'], 30)

    def test_tag_frequency_report_serializes_top_tags(self):
        response = self.client.get(reverse('reports:tag_frequency'), {'period': '365'})

        labels = json.loads(response.context['chart_labels_json'])
        data = json.loads(response.context['chart_data_json'])

        self.assertEqual(labels[0], 'API')
        self.assertEqual(data[0], 2)

    def test_dashboard_pdf_exports_pdf_response(self):
        class FakeHTML:
            def __init__(self, string, base_url):
                self.string = string
                self.base_url = base_url

            def write_pdf(self):
                return b'%PDF test'

        with patch.dict('sys.modules', {'weasyprint': SimpleNamespace(HTML=FakeHTML)}):
            response = self.client.get(reverse('reports:dashboard_pdf'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="threat-model-dashboard.pdf"')
        self.assertEqual(response.content, b'%PDF test')
