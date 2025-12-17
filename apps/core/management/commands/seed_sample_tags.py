"""
Management command to seed sample technology tags and assign them to threat models.
"""
import random
from django.core.management.base import BaseCommand
from django.utils.text import slugify
from apps.threatmodels.models import ThreatModel, TechnologyTag


class Command(BaseCommand):
    help = 'Seed sample technology tags and assign them to existing threat models'

    def handle(self, *args, **options):
        self.stdout.write('Creating technology tags...')

        # Define sample tags
        tags_data = [
            ('API Gateway', 'API management and gateway services'),
            ('Message Queue', 'Message queuing systems like SQS, Kafka, RabbitMQ'),
            ('Container Platform', 'Container orchestration like EKS, ECS, Kubernetes'),
            ('Serverless', 'Serverless compute like Lambda, Cloud Functions'),
            ('Relational Database', 'SQL databases like RDS, PostgreSQL, MySQL'),
            ('NoSQL Database', 'NoSQL databases like DynamoDB, MongoDB'),
            ('Object Storage', 'Object storage like S3, GCS, Azure Blob'),
            ('CDN', 'Content delivery networks like CloudFront, Fastly'),
            ('Load Balancer', 'Load balancing services like ALB, NLB'),
            ('Authentication', 'Auth services like Cognito, Auth0, Okta'),
            ('CI/CD Pipeline', 'Continuous integration and deployment pipelines'),
            ('Kubernetes', 'Kubernetes clusters and workloads'),
            ('Microservices', 'Microservices architecture'),
            ('Mobile Backend', 'Mobile application backend services'),
            ('Web Application', 'Web application frontend and backend'),
            ('Data Pipeline', 'ETL and data processing pipelines'),
            ('Machine Learning', 'ML models and inference services'),
            ('VPN', 'VPN and network access services'),
            ('Secrets Management', 'Secrets and credential management'),
            ('Logging', 'Logging and observability infrastructure'),
            ('Cache', 'Caching services like Redis, ElastiCache'),
            ('Search', 'Search services like Elasticsearch, OpenSearch'),
            ('Email Service', 'Email sending services like SES'),
            ('DNS', 'DNS management and routing'),
            ('WAF', 'Web application firewall'),
        ]

        created_count = 0
        for name, description in tags_data:
            tag, created = TechnologyTag.objects.get_or_create(
                slug=slugify(name),
                defaults={
                    'name': name,
                    'description': description,
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f'  Created tag: {name}')

        self.stdout.write(self.style.SUCCESS(f'Created {created_count} new tags'))

        # Assign random tags to existing threat models
        self.stdout.write('Assigning tags to threat models...')

        all_tags = list(TechnologyTag.objects.all())
        threat_models = ThreatModel.objects.all()
        assigned_count = 0

        for tm in threat_models:
            # Skip if already has tags
            if tm.tags.exists():
                continue

            # Assign 1-4 random tags
            num_tags = random.randint(1, 4)
            selected_tags = random.sample(all_tags, min(num_tags, len(all_tags)))
            tm.tags.add(*selected_tags)
            assigned_count += 1

        self.stdout.write(self.style.SUCCESS(
            f'Assigned tags to {assigned_count} threat models'
        ))

        self.stdout.write('')
        self.stdout.write('Summary:')
        self.stdout.write(f'  Total tags: {TechnologyTag.objects.count()}')
        self.stdout.write(f'  Threat models with tags: {ThreatModel.objects.filter(tags__isnull=False).distinct().count()}')
