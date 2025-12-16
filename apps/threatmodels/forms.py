from django import forms
from .models import ThreatModel, Finding


class ThreatModelForm(forms.ModelForm):
    class Meta:
        model = ThreatModel
        fields = ['title', 'slug', 'business_unit', 'description', 'overall_risk', 'status']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 5}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['slug'].required = False
        self.fields['slug'].help_text = 'Leave blank to auto-generate from title'


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = [
            'threat_id', 'scenario', 'threat_object', 'mitre_technique',
            'threat_catalog_rating', 'stride_category', 'inherent_risk',
            'residual_risk', 'mitigations', 'owner'
        ]
        widgets = {
            'scenario': forms.Textarea(attrs={'rows': 3}),
            'mitigations': forms.Textarea(attrs={'rows': 4}),
        }
