import os

from django import forms
from .models import ThreatModel, Finding, Diagram


MAX_UPLOAD_SIZE = 10 * 1024 * 1024
ALLOWED_UPLOAD_TYPES = {
    '.gif': ('image/gif', (b'GIF87a', b'GIF89a')),
    '.jpeg': ('image/jpeg', (b'\xff\xd8\xff',)),
    '.jpg': ('image/jpeg', (b'\xff\xd8\xff',)),
    '.pdf': ('application/pdf', (b'%PDF-',)),
    '.png': ('image/png', (b'\x89PNG\r\n\x1a\n',)),
}


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
            ext = os.path.splitext(file.name)[1].lower()
            allowed_file_type = ALLOWED_UPLOAD_TYPES.get(ext)
            if allowed_file_type is None:
                raise forms.ValidationError(
                    'Unsupported file type. Allowed types: '
                    f'{", ".join(sorted(ALLOWED_UPLOAD_TYPES))}'
                )

            if file.size > MAX_UPLOAD_SIZE:
                raise forms.ValidationError('File size must be under 10MB.')

            content_type, signatures = allowed_file_type
            declared_content_type = getattr(file, 'content_type', None)
            if declared_content_type and declared_content_type != content_type:
                raise forms.ValidationError(
                    f'Uploaded file MIME type must be {content_type}.'
                )

            header = file.read(16)
            file.seek(0)
            if not any(header.startswith(signature) for signature in signatures):
                raise forms.ValidationError(
                    f'Uploaded file content does not match the {content_type} format.'
                )
        return file
