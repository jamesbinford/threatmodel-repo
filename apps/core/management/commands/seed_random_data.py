"""
Management command to seed random data for testing trend charts.
Generates 1000 findings spread across 12 months.
"""
import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import ThreatModel, Finding
from apps.mitre.models import Technique


class Command(BaseCommand):
    help = 'Seed 1000 random findings spread over 12 months for trend analysis'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=1000,
            help='Number of findings to create (default: 1000)'
        )

    def handle(self, *args, **options):
        count = options['count']
        self.stdout.write(f'Generating {count} random findings over 12 months...')

        # Get existing data
        users = list(User.objects.all())
        if not users:
            self.stdout.write(self.style.ERROR('No users found. Run seed_sample_data first.'))
            return

        business_units = list(BusinessUnit.objects.all())
        if not business_units:
            self.stdout.write(self.style.ERROR('No business units found. Run seed_sample_data first.'))
            return

        techniques = list(Technique.objects.all())

        # Data for generating random threat models and findings
        threat_model_prefixes = [
            'API Gateway', 'Authentication Service', 'Data Pipeline', 'Customer Portal',
            'Admin Dashboard', 'Reporting Engine', 'Notification Service', 'Search Platform',
            'Analytics Engine', 'File Storage', 'Message Queue', 'Cache Layer',
            'Load Balancer', 'CDN Configuration', 'Database Cluster', 'Microservice',
            'Mobile Backend', 'Web Application', 'Integration Hub', 'Event Processor',
            'Batch Processor', 'Real-time Sync', 'User Management', 'Access Control',
            'Audit Logger', 'Monitoring Stack', 'CI/CD Pipeline', 'Container Platform',
            'Serverless Functions', 'GraphQL API'
        ]

        threat_model_suffixes = [
            'Security Review', 'Risk Assessment', 'Threat Analysis', 'Security Audit',
            'Vulnerability Assessment', 'Penetration Test Review', 'Architecture Review'
        ]

        threat_objects = [
            'User credentials', 'Session tokens', 'API keys', 'Database records',
            'Customer PII', 'Financial data', 'Authentication system', 'Authorization logic',
            'Encryption keys', 'Audit logs', 'Configuration files', 'Network traffic',
            'File uploads', 'User sessions', 'Admin access', 'Service accounts',
            'Cloud resources', 'Container images', 'Secret storage', 'Backup data',
            'Transaction records', 'Payment information', 'Personal data', 'Health records'
        ]

        scenarios = [
            'An attacker exploits {obj} through SQL injection in the search functionality.',
            'Unauthorized access to {obj} via broken authentication mechanism.',
            'Cross-site scripting attack targets {obj} through user input fields.',
            'Man-in-the-middle attack intercepts {obj} due to weak TLS configuration.',
            'Brute force attack against {obj} exploiting weak password policy.',
            'Privilege escalation allows attacker to access {obj}.',
            'Insecure direct object reference exposes {obj} to unauthorized users.',
            'Server-side request forgery targets internal systems containing {obj}.',
            'XML external entity attack extracts {obj} from backend systems.',
            'Deserialization vulnerability allows remote code execution affecting {obj}.',
            'Race condition in transaction processing compromises {obj}.',
            'Cache poisoning attack redirects users and exposes {obj}.',
            'Log injection attack manipulates audit records of {obj}.',
            'Path traversal attack accesses {obj} outside intended directory.',
            'Command injection through user input compromises {obj}.',
            'Insufficient logging fails to detect attack on {obj}.',
            'Weak cryptography exposes {obj} to offline attacks.',
            'Session fixation attack hijacks access to {obj}.',
            'CORS misconfiguration allows cross-origin access to {obj}.',
            'API rate limiting bypass enables enumeration of {obj}.'
        ]

        mitigations_options = [
            'Implement input validation and parameterized queries.',
            'Enable multi-factor authentication.',
            'Apply output encoding and content security policy.',
            'Enforce TLS 1.3 with strong cipher suites.',
            'Implement account lockout and rate limiting.',
            'Apply principle of least privilege.',
            'Use indirect references with authorization checks.',
            'Implement allowlist for outbound requests.',
            'Disable XML external entity processing.',
            'Use safe serialization libraries.',
            'Implement proper locking mechanisms.',
            'Use cryptographic cache keys.',
            'Sanitize log entries.',
            'Implement path canonicalization.',
            'Use parameterized commands.',
            'Implement comprehensive logging and monitoring.',
            'Upgrade to modern cryptographic algorithms.',
            'Regenerate session IDs on authentication.',
            'Configure strict CORS policies.',
            'Implement robust rate limiting.'
        ]

        owners = [
            'Platform Security Team', 'Application Security', 'Cloud Security Team',
            'DevSecOps Team', 'Security Engineering', 'Risk Management',
            'Compliance Team', 'Infrastructure Security', 'Network Security',
            'Data Protection Team', 'Identity Team', 'API Security Team'
        ]

        stride_categories = ['S', 'T', 'R', 'I', 'D', 'E']
        likelihood_choices = ['almost_certain', 'likely', 'possible', 'unlikely', 'rare']
        status_choices = ['draft', 'published', 'archived']

        # Calculate date range (last 12 months)
        end_date = timezone.now()
        start_date = end_date - timedelta(days=365)

        # Track created items
        created_threat_models = 0
        created_findings = 0

        # Create threat models and findings distributed over 12 months
        # We'll create roughly count/3 threat models, each with 2-5 findings
        target_findings = count
        findings_created = 0
        tm_counter = ThreatModel.objects.count() + 1

        self.stdout.write('Creating threat models and findings...')

        while findings_created < target_findings:
            # Random date within the last 12 months
            random_days = random.randint(0, 365)
            created_date = end_date - timedelta(days=random_days)

            # Create a threat model
            prefix = random.choice(threat_model_prefixes)
            suffix = random.choice(threat_model_suffixes)
            title = f'{prefix} {suffix} #{tm_counter}'
            # Sanitize slug: replace spaces and slashes with dashes
            slug_prefix = prefix.lower().replace(" ", "-").replace("/", "-")
            slug_suffix = suffix.lower().replace(" ", "-").replace("/", "-")
            slug = f'{slug_prefix}-{slug_suffix}-{tm_counter}'

            business_unit = random.choice(business_units)
            owner = random.choice(users)

            tm = ThreatModel.objects.create(
                title=title,
                slug=slug,
                business_unit=business_unit,
                description=f'Security assessment of the {prefix.lower()} component.\n\nThis review covers potential vulnerabilities and threats identified during the assessment period.',
                overall_risk=random.randint(1, 5),
                status=random.choice(status_choices),
                owner=owner
            )

            # Override the auto_now_add date
            ThreatModel.objects.filter(pk=tm.pk).update(
                created_at=created_date,
                updated_at=created_date + timedelta(days=random.randint(0, 30))
            )

            created_threat_models += 1
            tm_counter += 1

            # Create 2-5 findings for this threat model
            num_findings = random.randint(2, 5)
            remaining = target_findings - findings_created
            if num_findings > remaining:
                num_findings = remaining

            for f_num in range(1, num_findings + 1):
                threat_obj = random.choice(threat_objects)
                scenario_template = random.choice(scenarios)
                scenario = scenario_template.format(obj=threat_obj.lower())

                # Finding date is same as or after threat model date
                finding_date = created_date + timedelta(days=random.randint(0, 14))
                if finding_date > end_date:
                    finding_date = end_date

                inherent_risk = random.randint(1, 5)
                # 70% chance of having residual risk set
                residual_risk = random.randint(1, max(1, inherent_risk - 1)) if random.random() < 0.7 else None

                finding = Finding.objects.create(
                    threat_model=tm,
                    threat_id=f'TM-{tm_counter-1:03d}-F{f_num:02d}',
                    scenario=scenario,
                    threat_object=threat_obj,
                    mitre_technique=random.choice(techniques) if techniques and random.random() < 0.8 else None,
                    threat_catalog_rating=random.choice(likelihood_choices),
                    stride_category=random.choice(stride_categories),
                    inherent_risk=inherent_risk,
                    residual_risk=residual_risk,
                    mitigations=random.choice(mitigations_options) if random.random() < 0.8 else '',
                    owner=random.choice(owners)
                )

                # Override the auto_now_add date
                Finding.objects.filter(pk=finding.pk).update(
                    created_at=finding_date,
                    updated_at=finding_date + timedelta(days=random.randint(0, 7))
                )

                created_findings += 1
                findings_created += 1

            # Progress indicator
            if created_threat_models % 50 == 0:
                self.stdout.write(f'  Progress: {findings_created}/{target_findings} findings created')

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(f'Random data seeded successfully!'))
        self.stdout.write('')
        self.stdout.write('Summary:')
        self.stdout.write(f'  New Threat Models: {created_threat_models}')
        self.stdout.write(f'  New Findings: {created_findings}')
        self.stdout.write(f'  Total Threat Models: {ThreatModel.objects.count()}')
        self.stdout.write(f'  Total Findings: {Finding.objects.count()}')
