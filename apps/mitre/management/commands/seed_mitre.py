"""
Import MITRE ATT&CK and ATLAS framework data.

ATT&CK is imported from the official STIX bundle. ATLAS is imported from the
official ATLAS.yaml distribution. Local files can be supplied for repeatable
offline imports and tests.
"""
import json
from pathlib import Path
from urllib.request import urlopen

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.mitre.models import FrameworkImport, Tactic, Technique


DEFAULT_ATTACK_URL = (
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/'
    'enterprise-attack/enterprise-attack.json'
)
DEFAULT_ATLAS_URL = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml'


SAMPLE_ATTACK_DATA = {
    'id': 'sample-attack',
    'objects': [
        {
            'type': 'x-mitre-tactic',
            'name': 'Initial Access',
            'description': 'The adversary is trying to get into your network.',
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
            'name': 'Phishing',
            'description': 'Adversaries may send phishing messages to gain access.',
            'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}],
            'external_references': [
                {
                    'source_name': 'mitre-attack',
                    'external_id': 'T1566',
                    'url': 'https://attack.mitre.org/techniques/T1566/',
                }
            ],
        },
    ],
}

SAMPLE_ATLAS_DATA = {
    'version': 'sample',
    'matrices': [
        {
            'tactics': [
                {
                    'id': 'AML.TA0004',
                    'name': 'Initial Access',
                    'description': 'The adversary is trying to gain access to the AI system.',
                }
            ],
            'techniques': [
                {
                    'id': 'AML.T0043',
                    'name': 'Prompt Injection',
                    'description': 'Adversaries may craft malicious prompts to manipulate AI system behavior.',
                    'tactics': ['AML.TA0004'],
                }
            ],
        }
    ],
}


def external_reference_id(item, prefix):
    for reference in item.get('external_references', []):
        external_id = reference.get('external_id')
        if external_id and external_id.startswith(prefix):
            return external_id, reference.get('url', '')
    return None, ''


def read_source(path, url):
    if path:
        return Path(path).read_text(encoding='utf-8'), str(path)
    with urlopen(url, timeout=30) as response:
        return response.read().decode('utf-8'), url


def load_atlas_data(raw):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    try:
        import yaml
    except ImportError as exc:
        raise CommandError('PyYAML is required to import ATLAS.yaml. Install requirements.txt first.') from exc

    return yaml.safe_load(raw)


def stix_version(data):
    collection = next(
        (
            item for item in data.get('objects', [])
            if item.get('type') == 'x-mitre-collection' and item.get('x_mitre_version')
        ),
        None,
    )
    return collection.get('x_mitre_version', '') if collection else ''


def is_active(item):
    return not item.get('revoked') and not item.get('x_mitre_deprecated')


class Command(BaseCommand):
    help = 'Import MITRE ATT&CK and ATLAS tactics and techniques'

    def add_arguments(self, parser):
        parser.add_argument('--attack-url', default=DEFAULT_ATTACK_URL)
        parser.add_argument('--atlas-url', default=DEFAULT_ATLAS_URL)
        parser.add_argument('--attack-file')
        parser.add_argument('--atlas-file')
        parser.add_argument('--sample', action='store_true', help='Load bundled sample data instead of remote sources')
        parser.add_argument('--skip-attack', action='store_true')
        parser.add_argument('--skip-atlas', action='store_true')

    def handle(self, *args, **options):
        if not options['skip_attack']:
            if options['sample']:
                attack_counts = self.import_attack(SAMPLE_ATTACK_DATA, 'sample')
            else:
                raw, source = read_source(options['attack_file'], options['attack_url'])
                attack_counts = self.import_attack(json.loads(raw), source)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Imported ATT&CK: {attack_counts['tactics']} tactics, {attack_counts['techniques']} techniques"
                )
            )

        if not options['skip_atlas']:
            if options['sample']:
                atlas_counts = self.import_atlas(SAMPLE_ATLAS_DATA, 'sample')
            else:
                raw, source = read_source(options['atlas_file'], options['atlas_url'])
                atlas_counts = self.import_atlas(load_atlas_data(raw), source)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Imported ATLAS: {atlas_counts['tactics']} tactics, {atlas_counts['techniques']} techniques"
                )
            )

    @transaction.atomic
    def import_attack(self, data, source):
        tactics_by_shortname = {}
        tactics_by_id = {}

        for item in data.get('objects', []):
            if item.get('type') != 'x-mitre-tactic' or not is_active(item):
                continue

            tactic_id, url = external_reference_id(item, 'TA')
            if not tactic_id:
                continue

            tactic, _created = Tactic.objects.update_or_create(
                tactic_id=tactic_id,
                defaults={
                    'name': item.get('name', tactic_id),
                    'description': item.get('description', ''),
                    'framework': 'attack',
                    'url': url,
                },
            )
            tactics_by_id[tactic_id] = tactic
            shortname = item.get('x_mitre_shortname')
            if shortname:
                tactics_by_shortname[shortname] = tactic

        technique_parent_ids = {}
        for item in data.get('objects', []):
            if item.get('type') != 'attack-pattern' or not is_active(item):
                continue

            technique_id, url = external_reference_id(item, 'T')
            if not technique_id:
                continue

            tactic = self.attack_tactic_for_item(item, tactics_by_shortname)
            if tactic is None:
                continue

            technique, _created = Technique.objects.update_or_create(
                technique_id=technique_id,
                defaults={
                    'name': item.get('name', technique_id),
                    'description': item.get('description', ''),
                    'framework': 'attack',
                    'tactic': tactic,
                    'url': url,
                },
            )
            if '.' in technique_id:
                technique_parent_ids[technique_id] = technique_id.rsplit('.', 1)[0]

        self.apply_parent_relationships(technique_parent_ids)
        version = stix_version(data)
        self.record_import('attack', version, source, len(tactics_by_id), Technique.objects.filter(framework='attack').count())
        return {'tactics': len(tactics_by_id), 'techniques': Technique.objects.filter(framework='attack').count()}

    def attack_tactic_for_item(self, item, tactics_by_shortname):
        for phase in item.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic = tactics_by_shortname.get(phase.get('phase_name'))
                if tactic:
                    return tactic
        return None

    @transaction.atomic
    def import_atlas(self, data, source):
        matrix = (data.get('matrices') or [{}])[0]
        tactics_by_id = {}

        for item in matrix.get('tactics', []):
            tactic_id = item.get('id')
            if not tactic_id:
                continue

            tactic, _created = Tactic.objects.update_or_create(
                tactic_id=tactic_id,
                defaults={
                    'name': item.get('name', tactic_id),
                    'description': item.get('description', ''),
                    'framework': 'atlas',
                    'url': f'https://atlas.mitre.org/tactics/{tactic_id}/',
                },
            )
            tactics_by_id[tactic_id] = tactic

        technique_parent_ids = {}
        for item in matrix.get('techniques', []):
            technique_id = item.get('id')
            if not technique_id:
                continue

            tactic_id = (item.get('tactics') or [None])[0]
            parent_id = item.get('specializes')
            if tactic_id is None and parent_id:
                parent = Technique.objects.filter(technique_id=parent_id).select_related('tactic').first()
                tactic = parent.tactic if parent else None
            else:
                tactic = tactics_by_id.get(tactic_id)
            if tactic is None:
                continue

            Technique.objects.update_or_create(
                technique_id=technique_id,
                defaults={
                    'name': item.get('name', technique_id),
                    'description': item.get('description', ''),
                    'framework': 'atlas',
                    'tactic': tactic,
                    'url': f'https://atlas.mitre.org/techniques/{technique_id}/',
                },
            )
            if parent_id:
                technique_parent_ids[technique_id] = parent_id

        self.apply_parent_relationships(technique_parent_ids)
        version = str(data.get('version', ''))
        self.record_import('atlas', version, source, len(tactics_by_id), Technique.objects.filter(framework='atlas').count())
        return {'tactics': len(tactics_by_id), 'techniques': Technique.objects.filter(framework='atlas').count()}

    def apply_parent_relationships(self, technique_parent_ids):
        for technique_id, parent_id in technique_parent_ids.items():
            Technique.objects.filter(technique_id=technique_id).update(
                parent=Technique.objects.filter(technique_id=parent_id).first()
            )

    def record_import(self, framework, version, source, tactic_count, technique_count):
        FrameworkImport.objects.update_or_create(
            framework=framework,
            defaults={
                'version': version,
                'source': source[:500],
                'imported_at': timezone.now(),
                'tactic_count': tactic_count,
                'technique_count': technique_count,
            },
        )
