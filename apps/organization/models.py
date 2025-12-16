from django.db import models
from django.urls import reverse
from mptt.models import MPTTModel, TreeForeignKey


class BusinessUnit(MPTTModel):
    """
    Flexible tree structure for Line of Business hierarchy.
    Uses MPTT for efficient tree queries (ancestors, descendants, etc.)
    """
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    parent = TreeForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children'
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class MPTTMeta:
        order_insertion_by = ['name']

    class Meta:
        verbose_name = 'Business Unit'
        verbose_name_plural = 'Business Units'

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('organization:detail', kwargs={'slug': self.slug})
