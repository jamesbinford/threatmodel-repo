"""
Management command to fix invalid slugs containing slashes.
"""
from django.core.management.base import BaseCommand
from apps.threatmodels.models import ThreatModel


class Command(BaseCommand):
    help = 'Fix threat model slugs containing invalid characters'

    def handle(self, *args, **options):
        bad_slugs = ThreatModel.objects.filter(slug__contains='/')
        count = bad_slugs.count()
        self.stdout.write(f'Found {count} threat models with invalid slugs')

        for tm in bad_slugs:
            old_slug = tm.slug
            new_slug = tm.slug.replace('/', '-')
            tm.slug = new_slug
            tm.save()
            self.stdout.write(f'  Fixed: {old_slug} -> {new_slug}')

        self.stdout.write(self.style.SUCCESS(f'Fixed {count} slugs'))
