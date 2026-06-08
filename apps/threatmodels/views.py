from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.utils.text import slugify
from django.shortcuts import get_object_or_404
from .models import ThreatModel, Finding, Diagram, Evidence
from .forms import ThreatModelForm, FindingForm, DiagramForm, EvidenceForm
from .mixins import ThreatModelEditRequiredMixin
from .policies import can_edit_threat_model


class ThreatModelListView(LoginRequiredMixin, ListView):
    model = ThreatModel
    template_name = 'threatmodels/list.html'
    context_object_name = 'threat_models'
    paginate_by = 20

    def get_queryset(self):
        queryset = ThreatModel.objects.select_related('business_unit', 'owner')
        status = self.request.GET.get('status')
        risk = self.request.GET.get('risk')
        bu = self.request.GET.get('business_unit')

        if status:
            queryset = queryset.filter(status=status)
        if risk:
            queryset = queryset.filter(overall_risk=risk)
        if bu:
            queryset = queryset.filter(business_unit_id=bu)

        return queryset


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
