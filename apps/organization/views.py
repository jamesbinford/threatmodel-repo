from django.views.generic import ListView, DetailView
from .models import BusinessUnit


class BusinessUnitListView(ListView):
    model = BusinessUnit
    template_name = 'organization/list.html'
    context_object_name = 'business_units'

    def get_queryset(self):
        return BusinessUnit.objects.filter(parent__isnull=True)


class BusinessUnitDetailView(DetailView):
    model = BusinessUnit
    template_name = 'organization/detail.html'
    context_object_name = 'business_unit'
    slug_url_kwarg = 'slug'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['threat_models'] = self.object.threat_models.select_related('owner')
        context['children'] = self.object.get_children()
        context['ancestors'] = self.object.get_ancestors()
        return context
