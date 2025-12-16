from django.views.generic import ListView, DetailView
from .models import Tactic, Technique


class TechniqueListView(ListView):
    model = Technique
    template_name = 'mitre/list.html'
    context_object_name = 'techniques'

    def get_queryset(self):
        queryset = Technique.objects.select_related('tactic', 'parent')
        framework = self.request.GET.get('framework')
        tactic = self.request.GET.get('tactic')

        if framework:
            queryset = queryset.filter(framework=framework)
        if tactic:
            queryset = queryset.filter(tactic_id=tactic)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['tactics'] = Tactic.objects.all()
        return context


class TacticDetailView(DetailView):
    model = Tactic
    template_name = 'mitre/tactic_detail.html'
    context_object_name = 'tactic'
    slug_field = 'tactic_id'
    slug_url_kwarg = 'tactic_id'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['techniques'] = self.object.techniques.filter(parent__isnull=True)
        return context


class TechniqueDetailView(DetailView):
    model = Technique
    template_name = 'mitre/technique_detail.html'
    context_object_name = 'technique'
    slug_field = 'technique_id'
    slug_url_kwarg = 'technique_id'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['findings'] = self.object.findings.select_related('threat_model')
        context['subtechniques'] = self.object.subtechniques.all()
        return context
