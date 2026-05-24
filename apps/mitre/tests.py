from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.organization.models import BusinessUnit
from apps.threatmodels.models import Finding, ThreatModel
from .models import Tactic, Technique


class MitreViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='analyst', password='pass12345')
        cls.attack_tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Initial access tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        cls.atlas_tactic = Tactic.objects.create(
            tactic_id='AML.TA0002',
            name='Initial Access',
            description='ML initial access tactic.',
            framework='atlas',
            url='https://atlas.mitre.org/tactics/AML.TA0002/',
        )
        cls.attack_technique = Technique.objects.create(
            technique_id='T1566',
            name='Phishing',
            description='Phishing technique.',
            framework='attack',
            tactic=cls.attack_tactic,
            url='https://attack.mitre.org/techniques/T1566/',
        )
        cls.subtechnique = Technique.objects.create(
            technique_id='T1566.001',
            name='Spearphishing Attachment',
            description='Spearphishing attachment technique.',
            framework='attack',
            tactic=cls.attack_tactic,
            parent=cls.attack_technique,
            url='https://attack.mitre.org/techniques/T1566/001/',
        )
        cls.atlas_technique = Technique.objects.create(
            technique_id='AML.T0043',
            name='Prompt Injection',
            description='Prompt injection technique.',
            framework='atlas',
            tactic=cls.atlas_tactic,
            url='https://atlas.mitre.org/techniques/AML.T0043/',
        )
        cls.business_unit = BusinessUnit.objects.create(name='Digital Banking', slug='digital-banking')
        cls.threat_model = ThreatModel.objects.create(
            title='Mobile Banking',
            slug='mobile-banking',
            business_unit=cls.business_unit,
            description='Mobile banking threat model.',
            owner=cls.user,
        )
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            threat_id='TM-001-F01',
            scenario='Phishing attack.',
            threat_object='User credentials',
            mitre_technique=cls.attack_technique,
            stride_category='S',
            inherent_risk=4,
            owner='Mobile Security Team',
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_technique_list_filters_by_framework(self):
        response = self.client.get(reverse('mitre:list'), {'framework': 'atlas'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['techniques']), [self.atlas_technique])

    def test_technique_list_filters_by_tactic(self):
        response = self.client.get(reverse('mitre:list'), {'tactic': self.attack_tactic.pk})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            list(response.context['techniques']),
            [self.attack_technique, self.subtechnique],
        )

    def test_tactic_detail_only_lists_parent_techniques(self):
        response = self.client.get(reverse('mitre:tactic_detail', kwargs={'tactic_id': self.attack_tactic.tactic_id}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['techniques']), [self.attack_technique])

    def test_technique_detail_lists_findings_and_subtechniques(self):
        response = self.client.get(
            reverse('mitre:technique_detail', kwargs={'technique_id': self.attack_technique.technique_id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['findings']), [self.finding])
        self.assertEqual(list(response.context['subtechniques']), [self.subtechnique])
