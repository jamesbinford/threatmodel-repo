import json
from io import StringIO
from tempfile import TemporaryDirectory

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from apps.organization.models import BusinessUnit
from apps.threatmodels.models import Finding, ThreatModel
from .models import FrameworkImport, Tactic, Technique


def attack_bundle(technique_name='Phishing'):
    return {
        'objects': [
            {
                'type': 'x-mitre-collection',
                'x_mitre_version': '18.1',
            },
            {
                'type': 'x-mitre-tactic',
                'name': 'Initial Access',
                'description': 'Initial access tactic.',
                'x_mitre_shortname': 'initial-access',
                'external_references': [
                    {
                        'source_name': 'mitre-attack',
                        'external_id': 'TA0001',
                        'url': 'https://attack.mitre.org/tactics/TA0001/',
                    }
                ],
            },
            {
                'type': 'attack-pattern',
                'name': technique_name,
                'description': 'Phishing technique.',
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}
                ],
                'external_references': [
                    {
                        'source_name': 'mitre-attack',
                        'external_id': 'T1566',
                        'url': 'https://attack.mitre.org/techniques/T1566/',
                    }
                ],
            },
            {
                'type': 'attack-pattern',
                'name': 'Spearphishing Attachment',
                'description': 'Spearphishing attachment technique.',
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}
                ],
                'external_references': [
                    {
                        'source_name': 'mitre-attack',
                        'external_id': 'T1566.001',
                        'url': 'https://attack.mitre.org/techniques/T1566/001/',
                    }
                ],
            },
        ]
    }


def atlas_bundle():
    return {
        'version': '5.6.0',
        'matrices': [
            {
                'tactics': [
                    {
                        'id': 'AML.TA0004',
                        'name': 'Initial Access',
                        'description': 'Initial access to an AI system.',
                    }
                ],
                'techniques': [
                    {
                        'id': 'AML.T0043',
                        'name': 'Prompt Injection',
                        'description': 'Prompt injection technique.',
                        'tactics': ['AML.TA0004'],
                    },
                    {
                        'id': 'AML.T0043.000',
                        'name': 'Direct Prompt Injection',
                        'description': 'Direct prompt injection subtechnique.',
                        'specializes': 'AML.T0043',
                    },
                ],
            }
        ],
    }


class MitreImportCommandTests(TestCase):
    def write_json(self, directory, filename, data):
        path = f'{directory}/{filename}'
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        return path

    def test_seed_mitre_imports_attack_stix_and_tracks_version(self):
        with TemporaryDirectory() as directory:
            attack_path = self.write_json(directory, 'enterprise-attack.json', attack_bundle())
            call_command('seed_mitre', attack_file=attack_path, skip_atlas=True, stdout=StringIO())

        tactic = Tactic.objects.get(tactic_id='TA0001')
        technique = Technique.objects.get(technique_id='T1566')
        subtechnique = Technique.objects.get(technique_id='T1566.001')
        metadata = FrameworkImport.objects.get(framework='attack')

        self.assertEqual(tactic.name, 'Initial Access')
        self.assertEqual(technique.tactic, tactic)
        self.assertEqual(subtechnique.parent, technique)
        self.assertEqual(metadata.version, '18.1')
        self.assertEqual(metadata.tactic_count, 1)
        self.assertEqual(metadata.technique_count, 2)

    def test_seed_mitre_imports_atlas_data_and_tracks_version(self):
        with TemporaryDirectory() as directory:
            atlas_path = self.write_json(directory, 'ATLAS.json', atlas_bundle())
            call_command('seed_mitre', atlas_file=atlas_path, skip_attack=True, stdout=StringIO())

        tactic = Tactic.objects.get(tactic_id='AML.TA0004')
        technique = Technique.objects.get(technique_id='AML.T0043')
        subtechnique = Technique.objects.get(technique_id='AML.T0043.000')
        metadata = FrameworkImport.objects.get(framework='atlas')

        self.assertEqual(tactic.framework, 'atlas')
        self.assertEqual(technique.tactic, tactic)
        self.assertEqual(subtechnique.parent, technique)
        self.assertEqual(metadata.version, '5.6.0')

    def test_seed_mitre_updates_existing_techniques_without_breaking_findings(self):
        user = User.objects.create_user(username='analyst', password='pass12345')
        business_unit = BusinessUnit.objects.create(name='Digital Banking', slug='digital-banking')
        tactic = Tactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Old tactic.',
            framework='attack',
            url='https://attack.mitre.org/tactics/TA0001/',
        )
        technique = Technique.objects.create(
            technique_id='T1566',
            name='Old Phishing',
            description='Old description.',
            framework='attack',
            tactic=tactic,
            url='https://attack.mitre.org/techniques/T1566/',
        )
        threat_model = ThreatModel.objects.create(
            title='Mobile Banking',
            slug='mobile-banking',
            business_unit=business_unit,
            description='Mobile banking threat model.',
            owner=user,
        )
        finding = Finding.objects.create(
            threat_model=threat_model,
            threat_id='TM-001-F01',
            scenario='Phishing attack.',
            threat_object='User credentials',
            mitre_technique=technique,
            stride_category='S',
            inherent_risk=4,
            owner='Mobile Security Team',
        )

        with TemporaryDirectory() as directory:
            attack_path = self.write_json(directory, 'enterprise-attack.json', attack_bundle('Updated Phishing'))
            call_command('seed_mitre', attack_file=attack_path, skip_atlas=True, stdout=StringIO())

        finding.refresh_from_db()
        technique.refresh_from_db()
        self.assertEqual(finding.mitre_technique_id, technique.id)
        self.assertEqual(technique.name, 'Updated Phishing')


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
