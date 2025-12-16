from django.views.generic import ListView, DetailView, CreateView, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy, reverse
from django.utils.text import slugify
from .models import ThreatModel, Finding
from .forms import ThreatModelForm, FindingForm


class ThreatModelListView(ListView):
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


class ThreatModelDetailView(DetailView):
    model = ThreatModel
    template_name = 'threatmodels/detail.html'
    context_object_name = 'threat_model'
    slug_url_kwarg = 'slug'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['findings'] = self.object.findings.select_related('mitre_technique')
        context['diagrams'] = self.object.diagrams.all()
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


class ThreatModelUpdateView(LoginRequiredMixin, UpdateView):
    model = ThreatModel
    form_class = ThreatModelForm
    template_name = 'threatmodels/form.html'
    slug_url_kwarg = 'slug'


class FindingCreateView(LoginRequiredMixin, CreateView):
    model = Finding
    form_class = FindingForm
    template_name = 'threatmodels/finding_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = ThreatModel.objects.get(slug=self.kwargs['slug'])
        return context

    def form_valid(self, form):
        form.instance.threat_model = ThreatModel.objects.get(slug=self.kwargs['slug'])
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.kwargs['slug']})


class FindingUpdateView(LoginRequiredMixin, UpdateView):
    model = Finding
    form_class = FindingForm
    template_name = 'threatmodels/finding_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_model'] = self.object.threat_model
        return context

    def get_success_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.object.threat_model.slug})
