# Security Best Practices Report

## Executive Summary

The reviewed Django application now has strong authentication, authorization, upload validation, and production setting defaults. The remaining material gaps are in deployment/data-access controls: ALB HTTPS is not provisioned in Terraform, uploaded sensitive files are exposed through direct storage URLs instead of app-level authorization gates, and RDS encryption/deletion safeguards are not explicitly enabled.

## High Severity

### SBP-1: ALB Does Not Enforce HTTPS

- GitHub issue: #14
- Location: `terraform/alb.tf:39`, `terraform/alb.tf:51`, `threatmodel/settings/production.py:72`
- Evidence: Terraform actively forwards port 80 traffic to the app, while the HTTPS listener is commented out. Production Django settings default to SSL redirect, secure cookies, and HSTS.
- Impact: A production deployment can serve authenticated traffic over plaintext HTTP or fail because app-level HTTPS redirect has no ALB TLS listener to terminate at.
- Fix: Add an ACM-backed HTTPS listener, redirect HTTP to HTTPS, and document `SECURE_PROXY_SSL_HEADER_ENABLED=True` for ALB TLS termination.

### SBP-2: Uploaded Files Bypass App-Level Authorization After Link Disclosure

- GitHub issue: #16
- Location: `apps/threatmodels/templates/threatmodels/detail.html:110`, `apps/threatmodels/templates/threatmodels/detail.html:133`, `apps/threatmodels/templates/threatmodels/detail.html:246`
- Evidence: Diagram previews, diagram downloads, and evidence downloads render direct `file.url` links.
- Impact: Sensitive diagrams and mitigation evidence can be copied, logged, or forwarded, and access is no longer checked by Django RBAC at file access time.
- Fix: Add authenticated file access views for `Diagram` and `Evidence`, enforce object-level view policy, and serve files or redirect to short-lived signed URLs only after authorization.

## Medium Severity

### SBP-3: RDS Encryption And Deletion-Safety Controls Are Not Explicit

- GitHub issue: #15
- Location: `terraform/rds.tf:13`, `terraform/rds.tf:29`, `terraform/rds.tf:33`
- Evidence: The RDS instance does not set `storage_encrypted` or `kms_key_id`; it sets `skip_final_snapshot = true` and `deletion_protection = false`.
- Impact: Sensitive threat model data has weaker at-rest and accidental-deletion safeguards than expected for production security data.
- Fix: Enable RDS storage encryption, add configurable KMS support, require production final snapshots, and enable deletion protection for production.

## Notes

- No committed `.env` secrets were found; only `.env.example` is tracked.
- Production Django settings require `SECRET_KEY` from the environment and default `DEBUG` to false.
- CSRF middleware, auth middleware, clickjacking protection, secure cookie settings, upload content validation, and RBAC checks are present.
