"""
Management command to seed sample data for testing.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import ThreatModel, Finding
from apps.mitre.models import Technique


class Command(BaseCommand):
    help = 'Seed sample data for testing the application'

    def handle(self, *args, **options):
        self.stdout.write('Creating sample data...')

        # Create test user if not exists
        user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@example.com',
                'is_staff': True,
                'is_superuser': True,
            }
        )
        if created:
            user.set_password('admin')
            user.save()
            self.stdout.write(self.style.SUCCESS('Created admin user (password: admin)'))
        else:
            self.stdout.write('Admin user already exists')

        # Create analyst user
        analyst, created = User.objects.get_or_create(
            username='analyst',
            defaults={
                'email': 'analyst@example.com',
                'first_name': 'Security',
                'last_name': 'Analyst',
            }
        )
        if created:
            analyst.set_password('analyst')
            analyst.save()
            self.stdout.write(self.style.SUCCESS('Created analyst user (password: analyst)'))

        # Create Business Unit hierarchy
        self.stdout.write('Creating business units...')

        # Top-level LoBs
        corporate, _ = BusinessUnit.objects.get_or_create(
            slug='corporate',
            defaults={'name': 'Corporate', 'description': 'Corporate functions and shared services'}
        )

        retail, _ = BusinessUnit.objects.get_or_create(
            slug='retail-banking',
            defaults={'name': 'Retail Banking', 'description': 'Consumer banking products and services'}
        )

        investment, _ = BusinessUnit.objects.get_or_create(
            slug='investment-banking',
            defaults={'name': 'Investment Banking', 'description': 'Investment and wealth management services'}
        )

        technology, _ = BusinessUnit.objects.get_or_create(
            slug='technology',
            defaults={'name': 'Technology', 'description': 'IT infrastructure and application development'}
        )

        # Sub-units under Retail Banking
        digital, _ = BusinessUnit.objects.get_or_create(
            slug='digital-banking',
            defaults={
                'name': 'Digital Banking',
                'description': 'Online and mobile banking platforms',
                'parent': retail
            }
        )

        payments, _ = BusinessUnit.objects.get_or_create(
            slug='payments',
            defaults={
                'name': 'Payments',
                'description': 'Payment processing and card services',
                'parent': retail
            }
        )

        lending, _ = BusinessUnit.objects.get_or_create(
            slug='lending',
            defaults={
                'name': 'Lending',
                'description': 'Consumer and mortgage lending',
                'parent': retail
            }
        )

        # Sub-units under Technology
        cloud, _ = BusinessUnit.objects.get_or_create(
            slug='cloud-platform',
            defaults={
                'name': 'Cloud Platform',
                'description': 'AWS and cloud infrastructure',
                'parent': technology
            }
        )

        security_ops, _ = BusinessUnit.objects.get_or_create(
            slug='security-operations',
            defaults={
                'name': 'Security Operations',
                'description': 'SOC and incident response',
                'parent': technology
            }
        )

        self.stdout.write(self.style.SUCCESS(f'Created {BusinessUnit.objects.count()} business units'))

        # Get some MITRE techniques for linking
        phishing = Technique.objects.filter(technique_id='T1566').first()
        spearphishing = Technique.objects.filter(technique_id='T1566.001').first()
        brute_force = Technique.objects.filter(technique_id='T1110').first()
        credential_dump = Technique.objects.filter(technique_id='T1003').first()
        ransomware = Technique.objects.filter(technique_id='T1486').first()
        exploit = Technique.objects.filter(technique_id='T1190').first()
        prompt_injection = Technique.objects.filter(technique_id='AML.T0043').first()

        # Create Threat Models
        self.stdout.write('Creating threat models...')

        # Threat Model 1: Mobile Banking App
        tm1, created = ThreatModel.objects.get_or_create(
            slug='mobile-banking-app-v2',
            defaults={
                'title': 'Mobile Banking App v2.0',
                'business_unit': digital,
                'description': '''Threat model for the upcoming release of Mobile Banking App version 2.0.

This release includes new features:
- Biometric authentication (Face ID / Fingerprint)
- Real-time transaction notifications
- P2P payment integration
- Investment portfolio view

The app communicates with backend services via REST APIs over TLS 1.3.''',
                'overall_risk': 4,
                'status': 'published',
                'owner': analyst,
            }
        )

        if created:
            # Add findings to TM1
            Finding.objects.create(
                threat_model=tm1,
                threat_id='TM-001-F01',
                scenario='An attacker sends a phishing SMS with a link to a fake login page that harvests credentials.',
                threat_object='User credentials',
                mitre_technique=phishing,
                threat_catalog_rating='likely',
                stride_category='S',
                inherent_risk=4,
                residual_risk=2,
                mitigations='''1. Implement SMS link warnings in the app
2. Add anti-phishing education in onboarding
3. Enable push notification for login attempts
4. Implement device binding''',
                owner='Mobile Security Team'
            )

            Finding.objects.create(
                threat_model=tm1,
                threat_id='TM-001-F02',
                scenario='An attacker attempts brute force attack against user accounts via the login API.',
                threat_object='User accounts',
                mitre_technique=brute_force,
                threat_catalog_rating='possible',
                stride_category='S',
                inherent_risk=4,
                residual_risk=1,
                mitigations='''1. Rate limiting on login endpoint (5 attempts/minute)
2. Account lockout after 10 failed attempts
3. CAPTCHA after 3 failed attempts
4. Implement progressive delays''',
                owner='API Security Team'
            )

            Finding.objects.create(
                threat_model=tm1,
                threat_id='TM-001-F03',
                scenario='Sensitive data is logged in application logs and exposed through log aggregation systems.',
                threat_object='PII and transaction data',
                mitre_technique=None,
                threat_catalog_rating='possible',
                stride_category='I',
                inherent_risk=3,
                mitigations='''1. Implement log sanitization library
2. Add PII detection in CI/CD pipeline
3. Encrypt logs at rest''',
                owner='Platform Team'
            )

            Finding.objects.create(
                threat_model=tm1,
                threat_id='TM-001-F04',
                scenario='Attacker exploits biometric bypass on rooted/jailbroken devices.',
                threat_object='Authentication mechanism',
                mitre_technique=None,
                threat_catalog_rating='unlikely',
                stride_category='E',
                inherent_risk=5,
                residual_risk=2,
                mitigations='''1. Implement root/jailbreak detection
2. Disable biometric auth on compromised devices
3. Require PIN fallback on suspicious devices''',
                owner='Mobile Security Team'
            )

            self.stdout.write(f'  Created: {tm1.title} with 4 findings')

        # Threat Model 2: Payment Gateway
        tm2, created = ThreatModel.objects.get_or_create(
            slug='payment-gateway-integration',
            defaults={
                'title': 'Payment Gateway Integration',
                'business_unit': payments,
                'description': '''Threat model for the new real-time payment gateway integration with the Federal Reserve's FedNow service.

Architecture overview:
- Message queue for transaction processing
- HSM for cryptographic key management
- Real-time fraud detection engine
- Integration with existing core banking system''',
                'overall_risk': 5,
                'status': 'published',
                'owner': user,
            }
        )

        if created:
            Finding.objects.create(
                threat_model=tm2,
                threat_id='TM-002-F01',
                scenario='Attacker gains access to HSM keys through insider threat or compromised admin credentials.',
                threat_object='Cryptographic keys',
                mitre_technique=credential_dump,
                threat_catalog_rating='unlikely',
                stride_category='E',
                inherent_risk=5,
                mitigations='''1. Implement dual control for HSM access
2. Enable HSM audit logging
3. Quarterly access reviews
4. Background checks for HSM admins''',
                owner='Cryptography Team'
            )

            Finding.objects.create(
                threat_model=tm2,
                threat_id='TM-002-F02',
                scenario='Message queue poisoning leads to fraudulent transactions being processed.',
                threat_object='Transaction integrity',
                mitre_technique=None,
                threat_catalog_rating='possible',
                stride_category='T',
                inherent_risk=5,
                residual_risk=2,
                mitigations='''1. Message signing with HMAC
2. Schema validation on all messages
3. Anomaly detection on transaction patterns
4. Real-time alerting for unusual volumes''',
                owner='Integration Team'
            )

            Finding.objects.create(
                threat_model=tm2,
                threat_id='TM-002-F03',
                scenario='DDoS attack on payment gateway causes service disruption during peak hours.',
                threat_object='Service availability',
                mitre_technique=None,
                threat_catalog_rating='likely',
                stride_category='D',
                inherent_risk=4,
                residual_risk=2,
                mitigations='''1. AWS Shield Advanced
2. Auto-scaling configuration
3. Geographic load balancing
4. Circuit breaker patterns''',
                owner='Platform Team'
            )

            self.stdout.write(f'  Created: {tm2.title} with 3 findings')

        # Threat Model 3: Cloud Migration
        tm3, created = ThreatModel.objects.get_or_create(
            slug='core-banking-cloud-migration',
            defaults={
                'title': 'Core Banking Cloud Migration',
                'business_unit': cloud,
                'description': '''Threat model for migrating core banking services from on-premises data centers to AWS.

Migration scope:
- Account management services
- Transaction processing
- Customer data warehouse
- Reporting and analytics

Timeline: Q2 2025 - Q4 2025''',
                'overall_risk': 4,
                'status': 'draft',
                'owner': analyst,
            }
        )

        if created:
            Finding.objects.create(
                threat_model=tm3,
                threat_id='TM-003-F01',
                scenario='Misconfigured S3 bucket exposes sensitive customer data publicly.',
                threat_object='Customer PII',
                mitre_technique=None,
                threat_catalog_rating='possible',
                stride_category='I',
                inherent_risk=5,
                mitigations='''1. S3 Block Public Access at org level
2. AWS Config rules for bucket policies
3. Automated scanning with Prowler
4. Encryption enforcement''',
                owner='Cloud Security Team'
            )

            Finding.objects.create(
                threat_model=tm3,
                threat_id='TM-003-F02',
                scenario='Attacker exploits vulnerable EC2 instance to pivot into VPC and access databases.',
                threat_object='Database servers',
                mitre_technique=exploit,
                threat_catalog_rating='possible',
                stride_category='E',
                inherent_risk=5,
                mitigations='''1. Private subnets for databases
2. Security groups with least privilege
3. AWS Systems Manager for patching
4. VPC Flow Logs monitoring''',
                owner='Cloud Platform Team'
            )

            self.stdout.write(f'  Created: {tm3.title} with 2 findings')

        # Threat Model 4: AI Chatbot
        tm4, created = ThreatModel.objects.get_or_create(
            slug='customer-service-ai-chatbot',
            defaults={
                'title': 'Customer Service AI Chatbot',
                'business_unit': digital,
                'description': '''Threat model for the new AI-powered customer service chatbot.

The chatbot uses a large language model to:
- Answer account balance inquiries
- Help with transaction disputes
- Provide product recommendations
- Schedule branch appointments

Integrates with CRM and core banking via API.''',
                'overall_risk': 3,
                'status': 'published',
                'owner': user,
            }
        )

        if created:
            Finding.objects.create(
                threat_model=tm4,
                threat_id='TM-004-F01',
                scenario='Attacker uses prompt injection to extract sensitive information or bypass controls.',
                threat_object='Customer data and system controls',
                mitre_technique=prompt_injection,
                threat_catalog_rating='likely',
                stride_category='I',
                inherent_risk=4,
                residual_risk=2,
                mitigations='''1. Input sanitization layer
2. Output filtering for PII
3. Prompt hardening techniques
4. Human review for sensitive actions
5. Rate limiting per session''',
                owner='AI/ML Security Team'
            )

            Finding.objects.create(
                threat_model=tm4,
                threat_id='TM-004-F02',
                scenario='Chatbot is manipulated to provide incorrect financial advice leading to customer harm.',
                threat_object='Customer trust and regulatory compliance',
                mitre_technique=None,
                threat_catalog_rating='possible',
                stride_category='R',
                inherent_risk=4,
                mitigations='''1. Disclaimer on all financial information
2. Escalation to human for advice requests
3. Logging all interactions
4. Regular bias and accuracy testing''',
                owner='Compliance Team'
            )

            self.stdout.write(f'  Created: {tm4.title} with 2 findings')

        # Threat Model 5: Ransomware Assessment
        tm5, created = ThreatModel.objects.get_or_create(
            slug='enterprise-ransomware-assessment',
            defaults={
                'title': 'Enterprise Ransomware Resilience Assessment',
                'business_unit': security_ops,
                'description': '''Assessment of enterprise-wide ransomware resilience across all critical systems.

Scope includes:
- Endpoint protection coverage
- Backup and recovery capabilities
- Network segmentation
- User awareness training effectiveness
- Incident response readiness''',
                'overall_risk': 4,
                'status': 'published',
                'owner': analyst,
            }
        )

        if created:
            Finding.objects.create(
                threat_model=tm5,
                threat_id='TM-005-F01',
                scenario='Ransomware spreads via spearphishing email with malicious attachment.',
                threat_object='Endpoint systems and data',
                mitre_technique=spearphishing,
                threat_catalog_rating='likely',
                stride_category='D',
                inherent_risk=5,
                residual_risk=3,
                mitigations='''1. Email attachment sandboxing
2. Macro execution policies
3. User phishing training
4. EDR with ransomware detection''',
                owner='Email Security Team'
            )

            Finding.objects.create(
                threat_model=tm5,
                threat_id='TM-005-F02',
                scenario='Ransomware encrypts production databases and backup systems simultaneously.',
                threat_object='Data availability',
                mitre_technique=ransomware,
                threat_catalog_rating='possible',
                stride_category='D',
                inherent_risk=5,
                residual_risk=2,
                mitigations='''1. Air-gapped backup copies
2. Immutable backup storage
3. Regular backup restoration tests
4. Network segmentation between prod and backup''',
                owner='Backup and Recovery Team'
            )

            Finding.objects.create(
                threat_model=tm5,
                threat_id='TM-005-F03',
                scenario='Attacker exfiltrates data before encryption for double extortion.',
                threat_object='Confidential business data',
                mitre_technique=None,
                threat_catalog_rating='likely',
                stride_category='I',
                inherent_risk=5,
                mitigations='''1. DLP policies on egress
2. Network traffic monitoring
3. Cloud access security broker
4. Data classification program''',
                owner='Data Protection Team'
            )

            self.stdout.write(f'  Created: {tm5.title} with 3 findings')

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('Sample data created successfully!'))
        self.stdout.write('')
        self.stdout.write('Summary:')
        self.stdout.write(f'  Users: {User.objects.count()}')
        self.stdout.write(f'  Business Units: {BusinessUnit.objects.count()}')
        self.stdout.write(f'  Threat Models: {ThreatModel.objects.count()}')
        self.stdout.write(f'  Findings: {Finding.objects.count()}')
        self.stdout.write('')
        self.stdout.write('Login credentials:')
        self.stdout.write('  admin / admin (superuser)')
        self.stdout.write('  analyst / analyst (regular user)')
