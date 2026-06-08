# Internal Threat Model Submission API Design

## Purpose

Expose an internal REST API for trusted service teams and automation systems to submit threat models, findings, and workflow updates without using the HTML UI. The API should reuse the current Django domain model, business-unit RBAC policy layer, MITRE lookup data, and remediation workflow fields.

## Framework Choice

Use Django REST Framework (DRF).

Reasons:

- Serializer validation maps well to nested threat model and finding submissions.
- Authentication and permission classes provide a clear place for Entra JWT validation and object-level authorization.
- DRF gives a stable structure for future schema generation, browsable development views, pagination, and versioning.

Required dependency:

```text
djangorestframework>=3.15
PyJWT[crypto]>=2.8
```

Settings addition:

```python
INSTALLED_APPS += ["rest_framework"]
```

## API Namespace

All endpoints live under:

```text
/api/internal/v1/
```

This keeps the surface explicitly internal and versioned.

## Authentication

Primary authentication should use Microsoft Entra workload identities with OAuth2 client credentials. Each submitting system gets its own Entra application/service principal or managed identity, and calls the API with an Entra-issued bearer access token.

Proposed model:

```text
InternalAPIClient
- name
- entra_app_id
- entra_object_id
- user -> auth.User
- business_unit_scope -> BusinessUnit, optional
- is_active
- last_used_at
- created_at
- expires_at, optional
```

Entra token handling:

- Clients send `Authorization: Bearer <access_token>`.
- The token must be issued by the expected Entra tenant.
- The token audience must match this API's Entra application ID URI or client ID.
- The token signature must validate against Entra signing keys.
- The token must contain the required application role, such as `ThreatModel.Submit`.
- The token `appid`, `azp`, or service principal object ID must map to an active `InternalAPIClient`.
- Resolve the mapped client to a Django user/service account so existing role mappings and policy helpers still apply.
- Update `last_used_at` on successful authentication.
- Reject inactive clients, expired tokens, wrong audience, wrong issuer, unknown callers, or missing roles.

Recommended Entra app roles:

```text
ThreatModel.Submit
ThreatModel.Read
ThreatModel.Admin
```

Expected Entra setup:

- Register the Threat Model Repository API as an Entra application.
- Expose application roles for submit/read/admin access.
- Register each source system as a separate Entra application or use its managed identity.
- Grant each source system only the API app role it needs.
- Configure the source workload to request tokens for this API using client credentials.
- Record the caller's application ID and service-principal object ID in `InternalAPIClient`.

Recommended credential posture:

- Prefer managed identity or workload identity federation where available.
- Prefer certificate credentials over client secrets when federation or managed identity is not available.
- Avoid shared "generic" service accounts; each calling system should have a distinct service principal.

DRF integration:

```text
EntraJWTAuthentication
InternalThreatModelPermission
```

Local hashed API tokens may be implemented as a development or break-glass fallback, but they should not be the primary production authentication mechanism.

Session authentication should not be enabled for these endpoints in production API settings. This avoids CSRF ambiguity for non-browser clients.

## Authorization

Reuse existing policy helpers:

- Create threat model: `can_create_threat_model(user, business_unit)`
- Update threat model: `can_edit_threat_model(user, threat_model)`
- Submit findings: `can_edit_threat_model(user, threat_model)`
- Read submitted model: `can_view_threat_model(user, threat_model)`

If an `InternalAPIClient` has `business_unit_scope`, requested business units must match or descend from that scope.

## Idempotency

The API must support safe retries.

Recommended identifiers:

- `ThreatModel.external_id`: stable source-system identifier, nullable unique.
- `Finding.external_id`: stable source-system identifier, unique per threat model.

Recommended request header:

```text
Idempotency-Key: <client-generated-key>
```

Phase 1 can rely on `external_id` for upsert behavior and log `Idempotency-Key` for audit. A later phase can add full idempotency response replay.

## Model Additions

Add fields before implementing the API:

```text
ThreatModel.external_id CharField(max_length=300, unique=True, null=True, blank=True)
ThreatModel.source_system CharField(max_length=100, blank=True)

Finding.external_id CharField(max_length=300, blank=True)
UniqueConstraint(threat_model, external_id) where external_id is not blank/null
```

Optional audit model:

```text
APISubmission
- request_id
- idempotency_key
- endpoint
- method
- user
- source_ip
- status_code
- threat_model
- created_at
```

Do not store full request payloads by default; submissions may contain sensitive architecture and risk data.

## Endpoints

### POST `/api/internal/v1/threat-models/`

Create or update a threat model by `external_id` when present, otherwise create by slug/title rules.

Request:

```json
{
  "external_id": "service-catalog:payments-api",
  "source_system": "service-catalog",
  "title": "Payments API",
  "slug": "payments-api",
  "business_unit": "payments",
  "description": "Threat model submitted from service catalog.",
  "status": "draft",
  "overall_risk": 4,
  "tags": ["API", "Payments"],
  "findings": [
    {
      "external_id": "payments-api-authz-001",
      "threat_id": "PAY-001",
      "scenario": "Broken authorization exposes payment data.",
      "threat_object": "Payments API",
      "stride_category": "E",
      "inherent_risk": 4,
      "residual_risk": null,
      "mitre_technique": "T1190",
      "owner": "AppSec",
      "status": "open",
      "due_date": "2026-07-15",
      "mitigations": ""
    }
  ]
}
```

Response `201 Created` or `200 OK`:

```json
{
  "id": 123,
  "external_id": "service-catalog:payments-api",
  "slug": "payments-api",
  "url": "/threatmodels/payments-api/",
  "created": true,
  "finding_count": 1,
  "computed_risk": 4,
  "computed_risk_label": "High"
}
```

### GET `/api/internal/v1/threat-models/{slug}/`

Return normalized threat model data, findings, workflow status, computed risk, and links to the HTML detail page.

### POST `/api/internal/v1/threat-models/{slug}/findings/`

Create or update findings for one existing threat model.

Request:

```json
{
  "findings": [
    {
      "external_id": "payments-api-authz-001",
      "threat_id": "PAY-001",
      "scenario": "Broken authorization exposes payment data.",
      "threat_object": "Payments API",
      "stride_category": "E",
      "inherent_risk": 4,
      "status": "in_progress"
    }
  ]
}
```

Response:

```json
{
  "threat_model": "payments-api",
  "created": 0,
  "updated": 1,
  "findings": [
    {
      "external_id": "payments-api-authz-001",
      "threat_id": "PAY-001",
      "status": "in_progress"
    }
  ]
}
```

### GET `/api/internal/v1/reference/`

Return reference values for clients.

Response:

```json
{
  "risk": [
    {"value": 1, "label": "Very Low"},
    {"value": 2, "label": "Low"},
    {"value": 3, "label": "Medium"},
    {"value": 4, "label": "High"},
    {"value": 5, "label": "Critical"}
  ],
  "threat_model_statuses": ["draft", "published", "archived"],
  "finding_statuses": ["open", "in_progress", "mitigated", "accepted", "closed"],
  "stride_categories": ["S", "T", "R", "I", "D", "E"],
  "business_units": [
    {"slug": "payments", "name": "Payments"}
  ],
  "tags": ["API", "Payments"],
  "mitre_techniques": [
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "framework": "attack"}
  ]
}
```

## Validation Rules

- `business_unit` resolves by slug.
- `tags` must already exist in phase 1. Auto-create can be considered later if a trusted taxonomy owner needs it.
- `mitre_technique` resolves by MITRE technique ID.
- `overall_risk`, `inherent_risk`, and `residual_risk` must be 1-5 when provided.
- `status` values must match model choices.
- `due_date` must be ISO `YYYY-MM-DD`.
- `slug` is optional. If omitted on create, generate it from title using current behavior.
- If `external_id` identifies an existing record, update only fields included in the request.
- Nested findings should be processed transactionally with the parent threat model.

## Error Format

Use DRF serializer validation errors:

```json
{
  "business_unit": ["Unknown business unit slug: payments-prod"],
  "findings": [
    {
      "mitre_technique": ["Unknown MITRE technique ID: T9999"]
    }
  ]
}
```

HTTP status expectations:

- `400`: validation error
- `401`: missing/invalid token
- `403`: token user lacks role/scope
- `404`: requested threat model does not exist or is not visible
- `409`: conflicting identifier, such as slug already used by another external ID

## Security Requirements

- Require Entra bearer-token authentication on every internal API endpoint.
- Do not enable session auth for these endpoints.
- Do not log full payloads.
- Do not accept file uploads in v1.
- Apply object-level authorization before returning or mutating data.
- Validate JWT issuer, audience, signature, expiration, application role, and known caller mapping.
- Keep caller identities one-to-one with source systems for auditability.
- Add rate limiting later if endpoints become internet-reachable through VPN, gateway, or ALB routes.
- Keep this API separate from public UI URLs and document it as internal-only.

## Implementation Phases

### Phase 1: Foundation

- Add DRF dependency and settings.
- Add `apps/api` with `urls.py`, serializers, authentication, permissions, and tests.
- Add `external_id` and `source_system` fields.
- Add `InternalAPIClient` model that maps Entra app/service-principal identifiers to Django service users and optional business-unit scope.
- Implement Entra JWT authentication with configurable tenant ID, issuer, audience, and JWKS cache.
- Implement reference endpoint.

### Phase 2: Submission

- Implement threat model upsert endpoint.
- Implement nested finding upsert logic.
- Reuse `can_create_threat_model` and `can_edit_threat_model`.
- Add transaction coverage and validation tests.

### Phase 3: Readback And Operations

- Implement detail/readback endpoint.
- Add API submission audit metadata.
- Add operational docs and example client payloads.

### Phase 4: Hardening

- Add OpenAPI schema generation.
- Add idempotency response replay if needed.
- Add Entra client onboarding/admin UX and stale-client access reviews.
- Add optional local fallback token support only if operationally required.
- Add throttling if deployed beyond a tightly controlled internal network.
