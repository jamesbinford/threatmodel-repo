from django.db import models
from django.urls import reverse


class Tactic(models.Model):
    """MITRE ATT&CK/ATLAS Tactic."""
    FRAMEWORK_CHOICES = [
        ('attack', 'MITRE ATT&CK'),
        ('atlas', 'MITRE ATLAS'),
    ]

    tactic_id = models.CharField(max_length=20, unique=True)  # e.g., TA0001
    name = models.CharField(max_length=100)
    description = models.TextField()
    framework = models.CharField(max_length=10, choices=FRAMEWORK_CHOICES)
    url = models.URLField()

    class Meta:
        ordering = ['tactic_id']

    def __str__(self):
        return f"{self.tactic_id} - {self.name}"

    def get_absolute_url(self):
        return reverse('mitre:tactic_detail', kwargs={'tactic_id': self.tactic_id})


class Technique(models.Model):
    """MITRE ATT&CK/ATLAS Technique."""
    FRAMEWORK_CHOICES = [
        ('attack', 'MITRE ATT&CK'),
        ('atlas', 'MITRE ATLAS'),
    ]

    technique_id = models.CharField(max_length=20, unique=True)  # e.g., T1566
    name = models.CharField(max_length=200)
    description = models.TextField()
    framework = models.CharField(max_length=10, choices=FRAMEWORK_CHOICES)
    tactic = models.ForeignKey(
        Tactic,
        on_delete=models.CASCADE,
        related_name='techniques'
    )
    url = models.URLField()
    # For sub-techniques
    parent = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='subtechniques'
    )

    class Meta:
        ordering = ['technique_id']

    def __str__(self):
        return f"{self.technique_id} - {self.name}"

    def get_absolute_url(self):
        return reverse('mitre:technique_detail', kwargs={'technique_id': self.technique_id})

    @property
    def is_subtechnique(self):
        return self.parent is not None
