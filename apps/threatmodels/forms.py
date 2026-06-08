from django import forms
from .models import ThreatModel, Finding, Diagram, Evidence
from .upload_validation import validate_upload_file


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
            'residual_risk', 'mitigations', 'owner', 'owner_user',
            'status', 'due_date', 'resolution', 'acceptance_reason', 'verifier'
        ]
        widgets = {
            'scenario': forms.Textarea(attrs={'rows': 3}),
            'mitigations': forms.Textarea(attrs={'rows': 4}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
            'resolution': forms.Textarea(attrs={'rows': 3}),
            'acceptance_reason': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['status'].required = False
        self.fields['status'].initial = 'open'

    def clean_status(self):
        return self.cleaned_data.get('status') or 'open'


class DiagramForm(forms.ModelForm):
    class Meta:
        model = Diagram
        fields = ['title', 'diagram_type', 'file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_file(self):
        file = self.cleaned_data.get('file')
        return validate_upload_file(file)


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ['title', 'description', 'file']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_file(self):
        file = self.cleaned_data.get('file')
        return validate_upload_file(file)
