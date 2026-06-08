import csv

from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import HttpResponse
from django.urls import reverse
from django.utils.text import slugify
from django.shortcuts import get_object_or_404
from apps.mitre.models import Technique
from apps.organization.models import BusinessUnit
from .models import ThreatModel, Finding, Diagram, Evidence
from .models import TechnologyTag
from .forms import ThreatModelForm, FindingForm, DiagramForm, EvidenceForm
from .mixins import ThreatModelEditRequiredMixin
from .policies import can_edit_threat_model


class ThreatModelListView(LoginRequiredMixin, ListView):
    model = ThreatModel
    template_name = 'threatmodels/list.html'
    context_object_name = 'threat_models'
    paginate_by = 20

    def get_queryset(self):
        queryset = ThreatModel.objects.select_related(
            'business_unit', 'owner'
        ).prefetch_related('tags').annotate(
            finding_count=Count('findings', distinct=True)
        )
        query = self.request.GET.get('q', '').strip()
        status = self.request.GET.get('status')
        risk = self.request.GET.get('risk')
        bu = self.request.GET.get('business_unit')
        tag = self.request.GET.get('tag')
        owner = self.request.GET.get('owner')
        mitre = self.request.GET.get('mitre')

        if query:
            queryset = queryset.filter(
                Q(title__icontains=query)
                | Q(description__icontains=query)
                | Q(business_unit__name__icontains=query)
                | Q(owner__username__icontains=query)
                | Q(owner__first_name__icontains=query)
                | Q(owner__last_name__icontains=query)
                | Q(owner__email__icontains=query)
                | Q(tags__name__icontains=query)
                | Q(findings__threat_id__icontains=query)
                | Q(findings__scenario__icontains=query)
                | Q(findings__threat_object__icontains=query)
                | Q(findings__mitigations__icontains=query)
                | Q(findings__owner__icontains=query)
                | Q(findings__mitre_technique__technique_id__icontains=query)
                | Q(findings__mitre_technique__name__icontains=query)
            )
        if status:
            queryset = queryset.filter(status=status)
        if risk:
            queryset = queryset.filter(overall_risk=risk)
        if bu:
            queryset = queryset.filter(business_unit_id=bu)
        if tag:
            queryset = queryset.filter(tags__id=tag)
        if owner:
            queryset = queryset.filter(owner_id=owner)
        if mitre:
            queryset = queryset.filter(findings__mitre_technique_id=mitre)

        return queryset.distinct().order_by('-updated_at')

    def get(self, request, *args, **kwargs):
        if request.GET.get('export') == 'csv':
            return self.get_csv_response(self.get_queryset())
        return super().get(request, *args, **kwargs)

    def get_csv_response(self, queryset):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="threat-models.csv"'
        writer = csv.writer(response)
        writer.writerow([
            'Title',
            'Business Unit',
            'Status',
            'Manual Risk',
            'Computed Risk',
            'Finding Count',
            'Owner',
            'Tags',
            'Updated At',
        ])
        for threat_model in queryset:
            writer.writerow([
                threat_model.title,
                threat_model.business_unit.name,
                threat_model.get_status_display(),
                threat_model.risk_label,
                threat_model.computed_risk_label,
                threat_model.finding_count,
                threat_model.owner.username,
                ', '.join(tag.name for tag in threat_model.tags.all()),
                threat_model.updated_at.isoformat(),
            ])
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        query_params = self.request.GET.copy()
        query_params.pop('page', None)
        query_params.pop('export', None)
        context['filter_querystring'] = query_params.urlencode()
        export_params = query_params.copy()
        export_params['export'] = 'csv'
        context['export_querystring'] = export_params.urlencode()
        context['risk_choices'] = ThreatModel.RISK_CHOICES
        context['business_units'] = BusinessUnit.objects.all()
        context['technology_tags'] = TechnologyTag.objects.all()
        context['owners'] = User.objects.filter(
            owned_threat_models__isnull=False
        ).distinct().order_by('username')
        context['mitre_techniques'] = Technique.objects.filter(
            findings__isnull=False
        ).distinct().order_by('technique_id')
        return context


class ThreatModelDetailView(LoginRequiredMixin, DetailView):
    model = ThreatModel
    template_name = 'threatmodels/detail.html'
    context_object_name = 'threat_model'
    slug_url_kwarg = 'slug'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['findings'] = self.object.findings.select_related(
            'mitre_technique'
        ).prefetch_related('evidence__uploaded_by')
        context['diagrams'] = self.object.diagrams.all()
        context['can_edit_threat_model'] = can_edit_threat_model(self.request.user, self.object)
        return context


class ThreatModelCreateView(LoginRequiredMixin, CreateView):
    model = ThreatModel
    form_class = ThreatModelForm
    template_name = 'threatmodels/form.html'

    def get_initial(self):
        initial = super().get_initial()
        bu_id = self.request.GET.get('business_unit')
        if bu_id:
            initial['business_unit'] = bu_id
        return initial

    def form_valid(self, form):
        form.instance.owner = self.request.user
        if not form.instance.slug:
            form.instance.slug = slugify(form.instance.title)
        return super().form_valid(form)


class ThreatModelUpdateView(LoginRequiredMixin, ThreatModelEditRequiredMixin, UpdateView):
    model = ThreatModel
    form_class = ThreatModelForm
    template_name = 'threatmodels/form.html'
    slug_url_kwarg = 'slug'


class FindingCreateView(LoginRequiredMixin, ThreatModelEditRequiredMixin, CreateView):
    model = Finding
    form_class = FindingForm
    template_name = 'threatmodels/finding_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.threat_model
        return context

    def form_valid(self, form):
        form.instance.threat_model = self.threat_model
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.kwargs['slug']})


class FindingUpdateView(LoginRequiredMixin, ThreatModelEditRequiredMixin, UpdateView):
    model = Finding
    form_class = FindingForm
    template_name = 'threatmodels/finding_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.object.threat_model
        return context

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.object.threat_model.slug})


class DiagramUploadView(LoginRequiredMixin, ThreatModelEditRequiredMixin, CreateView):
    model = Diagram
    form_class = DiagramForm
    template_name = 'threatmodels/diagram_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.threat_model
        return context

    def form_valid(self, form):
        form.instance.threat_model = self.threat_model
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.kwargs['slug']})


class DiagramUpdateView(LoginRequiredMixin, ThreatModelEditRequiredMixin, UpdateView):
    model = Diagram
    form_class = DiagramForm
    template_name = 'threatmodels/diagram_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.object.threat_model
        return context

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.object.threat_model.slug})


class DiagramDeleteView(LoginRequiredMixin, ThreatModelEditRequiredMixin, DeleteView):
    model = Diagram
    template_name = 'threatmodels/diagram_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.object.threat_model
        return context

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.object.threat_model.slug})


class EvidenceUploadView(LoginRequiredMixin, ThreatModelEditRequiredMixin, CreateView):
    model = Evidence
    form_class = EvidenceForm
    template_name = 'threatmodels/evidence_form.html'

    def get_permission_threat_model(self):
        self.finding = get_object_or_404(
            Finding.objects.select_related('threat_model'),
            pk=self.kwargs['finding_pk'],
            threat_model__slug=self.kwargs['slug'],
        )
        return self.finding.threat_model

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.threat_model
        context['finding'] = self.finding
        return context

    def form_valid(self, form):
        form.instance.finding = self.finding
        form.instance.uploaded_by = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.threat_model.slug})
