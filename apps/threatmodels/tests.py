from tempfile import TemporaryDirectory

from django.contrib.auth.models import AnonymousUser, Group, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.accounts.models import RoleMapping
from apps.organization.models import BusinessUnit
from .forms import DiagramForm, FindingForm, ThreatModelForm
from .models import Diagram, Finding, ThreatModel
from .policies import (
    can_create_threat_model,
    can_edit_threat_model,
    can_manage_diagram,
    can_manage_finding,
    can_view_threat_model,
)


PNG_BYTES = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
JPEG_BYTES = b'\xff\xd8\xff\xe0\x00\x10JFIF'
GIF_BYTES = b'GIF89a\x01\x00\x01\x00'
PDF_BYTES = b'%PDF-1.7\n% test pdf'


def clean_upload_scanner(uploaded_file):
    uploaded_file.read()
    return True


def infected_upload_scanner(uploaded_file):
    uploaded_file.read()
    return False


class ThreatModelPolicyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.other_user = User.objects.create_user(username='other', password='pass12345')
        cls.staff_user = User.objects.create_user(
            username='staff',
            password='pass12345',
            is_staff=True,
        )
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.child_business_unit = BusinessUnit.objects.create(
            name='Payment APIs',
            slug='payment-apis',
            parent=cls.business_unit,
        )
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            overall_risk=4,
            owner=cls.owner,
        )
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            threat_id='TM-001-F01',
            scenario='An attacker abuses weak authorization.',
            threat_object='Payment API',
            stride_category='E',
            inherent_risk=4,
            owner='API Security Team',
        )
        cls.diagram = Diagram.objects.create(
            threat_model=cls.threat_model,
            title='Architecture',
            file='diagrams/architecture.png',
        )
        cls.child_threat_model = ThreatModel.objects.create(
            title='Payment API',
            slug='payment-api',
            business_unit=cls.child_business_unit,
            description='Payment API threat model.',
            overall_risk=3,
            owner=cls.owner,
        )

    def test_authenticated_users_can_view_threat_models(self):
        self.assertTrue(can_view_threat_model(self.owner, self.threat_model))
        self.assertTrue(can_view_threat_model(self.other_user, self.threat_model))

    def test_anonymous_users_cannot_view_or_create_threat_models(self):
        anonymous = AnonymousUser()

        self.assertFalse(can_view_threat_model(anonymous, self.threat_model))
        self.assertFalse(can_create_threat_model(anonymous))

    def test_authenticated_users_can_create_threat_models(self):
        self.assertTrue(can_create_threat_model(self.owner))

    def test_only_owner_or_staff_can_edit_threat_model(self):
        self.assertTrue(can_edit_threat_model(self.owner, self.threat_model))
        self.assertTrue(can_edit_threat_model(self.staff_user, self.threat_model))
        self.assertFalse(can_edit_threat_model(self.other_user, self.threat_model))

    def test_manage_child_object_policies_delegate_to_threat_model_edit_policy(self):
        self.assertTrue(can_manage_finding(self.owner, self.finding))
        self.assertTrue(can_manage_diagram(self.staff_user, self.diagram))
        self.assertFalse(can_manage_finding(self.other_user, self.finding))
        self.assertFalse(can_manage_diagram(self.other_user, self.diagram))

    def test_contributor_group_mapping_can_edit_scoped_threat_model(self):
        group = Group.objects.create(name='Payment Contributors')
        self.other_user.groups.add(group)
        RoleMapping.objects.create(
            name='Payment Contributors',
            group=group,
            role=RoleMapping.ROLE_CONTRIBUTOR,
            business_unit=self.business_unit,
        )

        self.assertTrue(can_edit_threat_model(self.other_user, self.threat_model))

    def test_business_unit_owner_mapping_applies_to_descendant_business_units(self):
        group = Group.objects.create(name='Payment Owners')
        self.other_user.groups.add(group)
        RoleMapping.objects.create(
            name='Payment Owners',
            group=group,
            role=RoleMapping.ROLE_BUSINESS_UNIT_OWNER,
            business_unit=self.business_unit,
        )

        self.assertTrue(can_edit_threat_model(self.other_user, self.child_threat_model))

    def test_inactive_mapping_does_not_grant_edit_access(self):
        group = Group.objects.create(name='Inactive Contributors')
        self.other_user.groups.add(group)
        RoleMapping.objects.create(
            name='Inactive Contributors',
            group=group,
            role=RoleMapping.ROLE_CONTRIBUTOR,
            business_unit=self.business_unit,
            is_active=False,
        )

        self.assertFalse(can_edit_threat_model(self.other_user, self.threat_model))

    def test_global_security_admin_mapping_can_edit_any_threat_model(self):
        group = Group.objects.create(name='Security Admins')
        self.other_user.groups.add(group)
        RoleMapping.objects.create(
            name='Security Admins',
            group=group,
            role=RoleMapping.ROLE_SECURITY_ADMIN,
        )

        self.assertTrue(can_edit_threat_model(self.other_user, self.threat_model))


class ThreatModelAuthorizationViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.other_user = User.objects.create_user(username='other', password='pass12345')
        cls.staff_user = User.objects.create_user(
            username='staff',
            password='pass12345',
            is_staff=True,
        )
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            owner=cls.owner,
        )
        cls.other_threat_model = ThreatModel.objects.create(
            title='Lending Platform',
            slug='lending-platform',
            business_unit=cls.business_unit,
            description='Lending platform threat model.',
            owner=cls.other_user,
        )
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            threat_id='TM-001-F01',
            scenario='An attacker abuses weak authorization.',
            threat_object='Payment API',
            stride_category='E',
            inherent_risk=4,
            owner='API Security Team',
        )
        cls.other_finding = Finding.objects.create(
            threat_model=cls.other_threat_model,
            threat_id='TM-002-F01',
            scenario='An attacker exfiltrates data.',
            threat_object='Loan API',
            stride_category='I',
            inherent_risk=4,
            owner='Platform Team',
        )
        cls.diagram = Diagram.objects.create(
            threat_model=cls.threat_model,
            title='Architecture',
            file='diagrams/architecture.png',
        )

    def test_owner_can_edit_threat_model_and_child_objects(self):
        self.client.force_login(self.owner)
        urls = [
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_add', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.finding.pk}),
            reverse('threatmodels:diagram_upload', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:diagram_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
            reverse('threatmodels:diagram_delete', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 200)

    def test_owner_can_delete_diagram(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('threatmodels:diagram_delete', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk})
        )

        self.assertRedirects(response, self.threat_model.get_absolute_url())
        self.assertFalse(Diagram.objects.filter(pk=self.diagram.pk).exists())

    def test_staff_can_edit_threat_model(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}))

        self.assertEqual(response.status_code, 200)

    def test_non_owner_cannot_edit_threat_model_or_child_objects(self):
        self.client.force_login(self.other_user)
        urls = [
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_add', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:finding_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.finding.pk}),
            reverse('threatmodels:diagram_upload', kwargs={'slug': self.threat_model.slug}),
            reverse('threatmodels:diagram_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
            reverse('threatmodels:diagram_delete', kwargs={'slug': self.threat_model.slug, 'pk': self.diagram.pk}),
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 403)

    def test_child_object_permission_uses_actual_parent_not_url_slug(self):
        self.client.force_login(self.owner)
        url = reverse(
            'threatmodels:finding_edit',
            kwargs={'slug': self.threat_model.slug, 'pk': self.other_finding.pk},
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 403)


class ThreatModelFormTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='owner', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')

    def test_threat_model_form_allows_blank_slug_for_auto_generation(self):
        form = ThreatModelForm(data={
            'title': 'Payment Gateway',
            'slug': '',
            'business_unit': self.business_unit.pk,
            'description': 'Payment gateway threat model.',
            'overall_risk': 4,
            'status': 'draft',
        })

        self.assertTrue(form.is_valid(), form.errors)

    def test_finding_form_accepts_minimum_required_fields(self):
        form = FindingForm(data={
            'threat_id': 'TM-001-F01',
            'scenario': 'An attacker abuses weak authorization.',
            'threat_object': 'Payment API',
            'stride_category': 'E',
            'inherent_risk': 4,
            'owner': 'API Security Team',
        })

        self.assertTrue(form.is_valid(), form.errors)

    def test_diagram_form_rejects_unsupported_file_extension(self):
        upload = SimpleUploadedFile('diagram.exe', b'not a diagram')
        form = DiagramForm(data={'title': 'Bad Diagram', 'diagram_type': 'other'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_diagram_form_rejects_supported_extension_with_wrong_content(self):
        upload = SimpleUploadedFile('diagram.png', b'not a diagram', content_type='image/png')
        form = DiagramForm(data={'title': 'Bad Diagram', 'diagram_type': 'other'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_diagram_form_rejects_supported_extension_with_wrong_content_type(self):
        upload = SimpleUploadedFile('diagram.png', PNG_BYTES, content_type='application/octet-stream')
        form = DiagramForm(data={'title': 'Bad Diagram', 'diagram_type': 'other'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_diagram_form_rejects_svg_uploads(self):
        upload = SimpleUploadedFile(
            'diagram.svg',
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
            content_type='image/svg+xml',
        )
        form = DiagramForm(data={'title': 'SVG Diagram', 'diagram_type': 'architecture'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_diagram_form_rejects_files_over_size_limit(self):
        upload = SimpleUploadedFile('large.png', b'x' * ((10 * 1024 * 1024) + 1))
        form = DiagramForm(data={'title': 'Large Diagram', 'diagram_type': 'architecture'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_diagram_form_accepts_supported_files_with_matching_content(self):
        uploads = [
            SimpleUploadedFile('diagram.png', PNG_BYTES, content_type='image/png'),
            SimpleUploadedFile('diagram.jpg', JPEG_BYTES, content_type='image/jpeg'),
            SimpleUploadedFile('diagram.gif', GIF_BYTES, content_type='image/gif'),
            SimpleUploadedFile('diagram.pdf', PDF_BYTES, content_type='application/pdf'),
        ]

        for upload in uploads:
            with self.subTest(filename=upload.name):
                form = DiagramForm(
                    data={'title': 'Architecture', 'diagram_type': 'architecture'},
                    files={'file': upload},
                )

                self.assertTrue(form.is_valid(), form.errors)

    @override_settings(UPLOAD_MALWARE_SCANNER='apps.threatmodels.tests.clean_upload_scanner')
    def test_diagram_form_accepts_files_that_pass_malware_scanning(self):
        upload = SimpleUploadedFile('diagram.png', PNG_BYTES, content_type='image/png')
        form = DiagramForm(data={'title': 'Architecture', 'diagram_type': 'architecture'}, files={'file': upload})

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(upload.tell(), 0)

    @override_settings(UPLOAD_MALWARE_SCANNER='apps.threatmodels.tests.infected_upload_scanner')
    def test_diagram_form_rejects_files_that_fail_malware_scanning(self):
        upload = SimpleUploadedFile('diagram.png', PNG_BYTES, content_type='image/png')
        form = DiagramForm(data={'title': 'Architecture', 'diagram_type': 'architecture'}, files={'file': upload})

        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)


class ThreatModelPostWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.other_user = User.objects.create_user(username='other', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            overall_risk=4,
            owner=cls.owner,
            status='draft',
        )
        cls.finding = Finding.objects.create(
            threat_model=cls.threat_model,
            threat_id='TM-001-F01',
            scenario='An attacker abuses weak authorization.',
            threat_object='Payment API',
            stride_category='E',
            inherent_risk=4,
            owner='API Security Team',
        )

    def test_create_threat_model_assigns_owner_and_generates_slug(self):
        self.client.force_login(self.owner)

        response = self.client.post(reverse('threatmodels:create'), data={
            'title': 'Mobile Banking App',
            'slug': '',
            'business_unit': self.business_unit.pk,
            'description': 'Mobile banking threat model.',
            'overall_risk': 3,
            'status': 'draft',
        })

        threat_model = ThreatModel.objects.get(slug='mobile-banking-app')
        self.assertRedirects(response, threat_model.get_absolute_url())
        self.assertEqual(threat_model.owner, self.owner)

    def test_owner_can_update_threat_model(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            data={
                'title': 'Payment Gateway Updated',
                'slug': self.threat_model.slug,
                'business_unit': self.business_unit.pk,
                'description': 'Updated description.',
                'overall_risk': 5,
                'status': 'published',
            },
        )

        self.threat_model.refresh_from_db()
        self.assertRedirects(response, self.threat_model.get_absolute_url())
        self.assertEqual(self.threat_model.title, 'Payment Gateway Updated')
        self.assertEqual(self.threat_model.overall_risk, 5)

    def test_non_owner_cannot_update_threat_model_with_post(self):
        self.client.force_login(self.other_user)

        response = self.client.post(
            reverse('threatmodels:edit', kwargs={'slug': self.threat_model.slug}),
            data={
                'title': 'Unauthorized Update',
                'slug': self.threat_model.slug,
                'business_unit': self.business_unit.pk,
                'description': 'Updated description.',
                'status': 'published',
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_owner_can_create_finding(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('threatmodels:finding_add', kwargs={'slug': self.threat_model.slug}),
            data={
                'threat_id': 'TM-001-F02',
                'scenario': 'Sensitive data is logged.',
                'threat_object': 'Application logs',
                'stride_category': 'I',
                'inherent_risk': 3,
                'residual_risk': '',
                'mitigations': 'Sanitize logs.',
                'owner': 'Platform Team',
            },
        )

        self.assertRedirects(response, self.threat_model.get_absolute_url())
        self.assertTrue(self.threat_model.findings.filter(threat_id='TM-001-F02').exists())

    def test_owner_can_update_finding(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('threatmodels:finding_edit', kwargs={'slug': self.threat_model.slug, 'pk': self.finding.pk}),
            data={
                'threat_id': self.finding.threat_id,
                'scenario': 'Updated scenario.',
                'threat_object': 'Payment API',
                'stride_category': 'E',
                'inherent_risk': 5,
                'residual_risk': 2,
                'mitigations': 'Add authorization checks.',
                'owner': 'API Security Team',
            },
        )

        self.finding.refresh_from_db()
        self.assertRedirects(response, self.threat_model.get_absolute_url())
        self.assertEqual(self.finding.scenario, 'Updated scenario.')
        self.assertEqual(self.finding.residual_risk, 2)

    def test_owner_can_upload_diagram(self):
        self.client.force_login(self.owner)
        with TemporaryDirectory() as media_root, override_settings(MEDIA_ROOT=media_root):
            response = self.client.post(
                reverse('threatmodels:diagram_upload', kwargs={'slug': self.threat_model.slug}),
                data={
                    'title': 'Architecture',
                    'diagram_type': 'architecture',
                    'description': 'Current architecture.',
                    'file': SimpleUploadedFile('architecture.png', PNG_BYTES, content_type='image/png'),
                },
            )

        self.assertRedirects(response, self.threat_model.get_absolute_url())
        self.assertTrue(self.threat_model.diagrams.filter(title='Architecture').exists())

    def test_threat_model_list_filters_by_status_risk_and_business_unit(self):
        self.client.force_login(self.owner)

        response = self.client.get(reverse('threatmodels:list'), {
            'status': 'draft',
            'risk': '4',
            'business_unit': self.business_unit.pk,
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['threat_models']), [self.threat_model])

    def test_create_threat_model_initializes_business_unit_from_query_string(self):
        self.client.force_login(self.owner)

        response = self.client.get(reverse('threatmodels:create'), {'business_unit': self.business_unit.pk})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].initial['business_unit'], str(self.business_unit.pk))


class DiagramRenderingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='pass12345')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')
        cls.threat_model = ThreatModel.objects.create(
            title='Payment Gateway',
            slug='payment-gateway',
            business_unit=cls.business_unit,
            description='Payment gateway threat model.',
            owner=cls.owner,
        )
        cls.image_diagram = Diagram.objects.create(
            threat_model=cls.threat_model,
            title='Architecture Image',
            file='diagrams/architecture.png',
        )
        cls.pdf_diagram = Diagram.objects.create(
            threat_model=cls.threat_model,
            title='Architecture PDF',
            file='diagrams/architecture.pdf',
        )

    def test_threat_model_detail_previews_images_but_not_pdfs(self):
        self.client.force_login(self.owner)

        response = self.client.get(reverse('threatmodels:detail', kwargs={'slug': self.threat_model.slug}))

        self.assertContains(response, '<img src="/media/diagrams/architecture.png"', html=False)
        self.assertNotContains(response, '<img src="/media/diagrams/architecture.pdf"', html=False)
        self.assertContains(response, 'href="/media/diagrams/architecture.pdf"', html=False)
