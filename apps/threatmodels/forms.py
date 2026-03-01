import os

from django import forms
from .models import ThreatModel, Finding, Diagram


class ThreatModelForm(forms.ModelForm):
    class Meta:
        model = ThreatModel
        fields = ['title', 'slug', 'business_unit', 'description', 'overall_risk', 'status', 'tags']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 5}),
            'tags': forms.CheckboxSelectMultiple(),
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


class DiagramForm(forms.ModelForm):
    class Meta:
        model = Diagram
        fields = ['title', 'diagram_type', 'file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            allowed_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf']
            ext = os.path.splitext(file.name)[1].lower()
            if ext not in allowed_extensions:
                raise forms.ValidationError(
                    f'Unsupported file type. Allowed types: {", ".join(allowed_extensions)}'
                )
            max_size = 10 * 1024 * 1024  # 10MB
            if file.size > max_size:
                raise forms.ValidationError('File size must be under 10MB.')
        return file
