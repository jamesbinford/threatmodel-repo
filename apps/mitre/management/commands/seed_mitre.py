"""
Management command to seed MITRE ATT&CK and ATLAS data.
This loads a representative sample of tactics and techniques.
For a full load, consider fetching from MITRE's STIX data.
"""
from django.core.management.base import BaseCommand
from apps.mitre.models import Tactic, Technique


class Command(BaseCommand):
    help = 'Seed the database with MITRE ATT&CK and ATLAS data'

    def handle(self, *args, **options):
        self.stdout.write('Seeding MITRE data...')

        # ATT&CK Tactics
        attack_tactics = [
            {
                'tactic_id': 'TA0001',
                'name': 'Initial Access',
                'description': 'The adversary is trying to get into your network.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0001/'
            },
            {
                'tactic_id': 'TA0002',
                'name': 'Execution',
                'description': 'The adversary is trying to run malicious code.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0002/'
            },
            {
                'tactic_id': 'TA0003',
                'name': 'Persistence',
                'description': 'The adversary is trying to maintain their foothold.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0003/'
            },
            {
                'tactic_id': 'TA0004',
                'name': 'Privilege Escalation',
                'description': 'The adversary is trying to gain higher-level permissions.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0004/'
            },
            {
                'tactic_id': 'TA0005',
                'name': 'Defense Evasion',
                'description': 'The adversary is trying to avoid being detected.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0005/'
            },
            {
                'tactic_id': 'TA0006',
                'name': 'Credential Access',
                'description': 'The adversary is trying to steal account names and passwords.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0006/'
            },
            {
                'tactic_id': 'TA0007',
                'name': 'Discovery',
                'description': 'The adversary is trying to figure out your environment.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0007/'
            },
            {
                'tactic_id': 'TA0008',
                'name': 'Lateral Movement',
                'description': 'The adversary is trying to move through your environment.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0008/'
            },
            {
                'tactic_id': 'TA0009',
                'name': 'Collection',
                'description': 'The adversary is trying to gather data of interest.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0009/'
            },
            {
                'tactic_id': 'TA0010',
                'name': 'Exfiltration',
                'description': 'The adversary is trying to steal data.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0010/'
            },
            {
                'tactic_id': 'TA0011',
                'name': 'Command and Control',
                'description': 'The adversary is trying to communicate with compromised systems.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0011/'
            },
            {
                'tactic_id': 'TA0040',
                'name': 'Impact',
                'description': 'The adversary is trying to manipulate, interrupt, or destroy systems and data.',
                'framework': 'attack',
                'url': 'https://attack.mitre.org/tactics/TA0040/'
            },
        ]

        # Create ATT&CK tactics
        tactic_objects = {}
        for tactic_data in attack_tactics:
            tactic, created = Tactic.objects.update_or_create(
                tactic_id=tactic_data['tactic_id'],
                defaults=tactic_data
            )
            tactic_objects[tactic_data['tactic_id']] = tactic
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  {status} tactic: {tactic}')

        # ATT&CK Techniques (sample)
        attack_techniques = [
            # Initial Access
            {
                'technique_id': 'T1566',
                'name': 'Phishing',
                'description': 'Adversaries may send phishing messages to gain access to victim systems.',
                'framework': 'attack',
                'tactic_id': 'TA0001',
                'url': 'https://attack.mitre.org/techniques/T1566/'
            },
            {
                'technique_id': 'T1566.001',
                'name': 'Spearphishing Attachment',
                'description': 'Adversaries may send spearphishing emails with a malicious attachment.',
                'framework': 'attack',
                'tactic_id': 'TA0001',
                'url': 'https://attack.mitre.org/techniques/T1566/001/',
                'parent_id': 'T1566'
            },
            {
                'technique_id': 'T1566.002',
                'name': 'Spearphishing Link',
                'description': 'Adversaries may send spearphishing emails with a malicious link.',
                'framework': 'attack',
                'tactic_id': 'TA0001',
                'url': 'https://attack.mitre.org/techniques/T1566/002/',
                'parent_id': 'T1566'
            },
            {
                'technique_id': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'description': 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system.',
                'framework': 'attack',
                'tactic_id': 'TA0001',
                'url': 'https://attack.mitre.org/techniques/T1190/'
            },
            # Execution
            {
                'technique_id': 'T1059',
                'name': 'Command and Scripting Interpreter',
                'description': 'Adversaries may abuse command and script interpreters to execute commands.',
                'framework': 'attack',
                'tactic_id': 'TA0002',
                'url': 'https://attack.mitre.org/techniques/T1059/'
            },
            {
                'technique_id': 'T1059.001',
                'name': 'PowerShell',
                'description': 'Adversaries may abuse PowerShell commands and scripts for execution.',
                'framework': 'attack',
                'tactic_id': 'TA0002',
                'url': 'https://attack.mitre.org/techniques/T1059/001/',
                'parent_id': 'T1059'
            },
            # Credential Access
            {
                'technique_id': 'T1110',
                'name': 'Brute Force',
                'description': 'Adversaries may use brute force techniques to gain access to accounts.',
                'framework': 'attack',
                'tactic_id': 'TA0006',
                'url': 'https://attack.mitre.org/techniques/T1110/'
            },
            {
                'technique_id': 'T1003',
                'name': 'OS Credential Dumping',
                'description': 'Adversaries may attempt to dump credentials to obtain account login information.',
                'framework': 'attack',
                'tactic_id': 'TA0006',
                'url': 'https://attack.mitre.org/techniques/T1003/'
            },
            # Lateral Movement
            {
                'technique_id': 'T1021',
                'name': 'Remote Services',
                'description': 'Adversaries may use valid accounts to log into a service for remote access.',
                'framework': 'attack',
                'tactic_id': 'TA0008',
                'url': 'https://attack.mitre.org/techniques/T1021/'
            },
            # Exfiltration
            {
                'technique_id': 'T1041',
                'name': 'Exfiltration Over C2 Channel',
                'description': 'Adversaries may steal data by exfiltrating it over an existing C2 channel.',
                'framework': 'attack',
                'tactic_id': 'TA0010',
                'url': 'https://attack.mitre.org/techniques/T1041/'
            },
            # Impact
            {
                'technique_id': 'T1486',
                'name': 'Data Encrypted for Impact',
                'description': 'Adversaries may encrypt data on target systems to interrupt availability.',
                'framework': 'attack',
                'tactic_id': 'TA0040',
                'url': 'https://attack.mitre.org/techniques/T1486/'
            },
        ]

        # First pass: create techniques without parent references
        technique_objects = {}
        for tech_data in attack_techniques:
            parent_id = tech_data.pop('parent_id', None)
            tactic = tactic_objects[tech_data.pop('tactic_id')]

            technique, created = Technique.objects.update_or_create(
                technique_id=tech_data['technique_id'],
                defaults={**tech_data, 'tactic': tactic}
            )
            technique_objects[tech_data['technique_id']] = (technique, parent_id)
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  {status} technique: {technique}')

        # Second pass: set parent references
        for technique_id, (technique, parent_id) in technique_objects.items():
            if parent_id and parent_id in technique_objects:
                parent_technique = technique_objects[parent_id][0]
                technique.parent = parent_technique
                technique.save()

        # ATLAS Tactics (AI-specific)
        atlas_tactics = [
            {
                'tactic_id': 'AML.TA0000',
                'name': 'ML Model Access',
                'description': 'Techniques to gain some level of access to a machine learning model.',
                'framework': 'atlas',
                'url': 'https://atlas.mitre.org/tactics/AML.TA0000'
            },
            {
                'tactic_id': 'AML.TA0001',
                'name': 'ML Attack Staging',
                'description': 'Techniques to prepare for an attack on a machine learning system.',
                'framework': 'atlas',
                'url': 'https://atlas.mitre.org/tactics/AML.TA0001'
            },
            {
                'tactic_id': 'AML.TA0002',
                'name': 'Initial Access',
                'description': 'Techniques to gain initial access to a machine learning system.',
                'framework': 'atlas',
                'url': 'https://atlas.mitre.org/tactics/AML.TA0002'
            },
        ]

        for tactic_data in atlas_tactics:
            tactic, created = Tactic.objects.update_or_create(
                tactic_id=tactic_data['tactic_id'],
                defaults=tactic_data
            )
            tactic_objects[tactic_data['tactic_id']] = tactic
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  {status} tactic: {tactic}')

        # ATLAS Techniques (sample)
        atlas_techniques = [
            {
                'technique_id': 'AML.T0000',
                'name': 'ML Supply Chain Compromise',
                'description': 'Adversaries may manipulate products or product delivery mechanisms prior to receipt.',
                'framework': 'atlas',
                'tactic_id': 'AML.TA0002',
                'url': 'https://atlas.mitre.org/techniques/AML.T0000'
            },
            {
                'technique_id': 'AML.T0010',
                'name': 'ML Model Inference API Access',
                'description': 'Adversaries may gain access to the inference API of a target model.',
                'framework': 'atlas',
                'tactic_id': 'AML.TA0000',
                'url': 'https://atlas.mitre.org/techniques/AML.T0010'
            },
            {
                'technique_id': 'AML.T0043',
                'name': 'Prompt Injection',
                'description': 'Adversaries may craft malicious prompts to manipulate AI system behavior.',
                'framework': 'atlas',
                'tactic_id': 'AML.TA0001',
                'url': 'https://atlas.mitre.org/techniques/AML.T0043'
            },
        ]

        for tech_data in atlas_techniques:
            tactic = tactic_objects[tech_data.pop('tactic_id')]

            technique, created = Technique.objects.update_or_create(
                technique_id=tech_data['technique_id'],
                defaults={**tech_data, 'tactic': tactic}
            )
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  {status} technique: {technique}')

        self.stdout.write(self.style.SUCCESS('MITRE data seeded successfully!'))
        self.stdout.write(f'  Total tactics: {Tactic.objects.count()}')
        self.stdout.write(f'  Total techniques: {Technique.objects.count()}')
