import os

from django import forms
from django.conf import settings
from django.utils.module_loading import import_string


MAX_UPLOAD_SIZE = 10 * 1024 * 1024

UPLOAD_TYPES = {
    ".png": {
        "label": "PNG image",
        "content_types": {"image/png"},
        "signatures": (b"\x89PNG\r\n\x1a\n",),
        "previewable": True,
    },
    ".jpg": {
        "label": "JPEG image",
        "content_types": {"image/jpeg"},
        "signatures": (b"\xff\xd8\xff",),
        "previewable": True,
    },
    ".jpeg": {
        "label": "JPEG image",
        "content_types": {"image/jpeg"},
        "signatures": (b"\xff\xd8\xff",),
        "previewable": True,
    },
    ".gif": {
        "label": "GIF image",
        "content_types": {"image/gif"},
        "signatures": (b"GIF87a", b"GIF89a"),
        "previewable": True,
    },
    ".pdf": {
        "label": "PDF document",
        "content_types": {"application/pdf"},
        "signatures": (b"%PDF-",),
        "previewable": False,
    },
}

ALLOWED_UPLOAD_EXTENSIONS = tuple(UPLOAD_TYPES.keys())
PREVIEWABLE_IMAGE_EXTENSIONS = tuple(
    ext for ext, config in UPLOAD_TYPES.items() if config["previewable"]
)


def upload_extension(filename):
    return os.path.splitext(filename or "")[1].lower()


def upload_type_config(filename):
    return UPLOAD_TYPES.get(upload_extension(filename))


def is_previewable_image(filename):
    return upload_extension(filename) in PREVIEWABLE_IMAGE_EXTENSIONS


def _read_signature(uploaded_file):
    position = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
    header = uploaded_file.read(512)
    if position is not None and hasattr(uploaded_file, "seek"):
        uploaded_file.seek(position)
    return header


def _scan_for_malware(uploaded_file):
    scanner_path = getattr(settings, "UPLOAD_MALWARE_SCANNER", None)
    if not scanner_path:
        return

    position = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
    scanner = import_string(scanner_path)
    is_clean = scanner(uploaded_file)
    if position is not None and hasattr(uploaded_file, "seek"):
        uploaded_file.seek(position)

    if is_clean is not True:
        raise forms.ValidationError("Uploaded file failed malware scanning.")


def validate_upload_file(uploaded_file):
    if not uploaded_file:
        return uploaded_file

    config = upload_type_config(uploaded_file.name)
    if config is None:
        allowed = ", ".join(ALLOWED_UPLOAD_EXTENSIONS)
        raise forms.ValidationError(f"Unsupported file type. Allowed types: {allowed}.")

    if uploaded_file.size > MAX_UPLOAD_SIZE:
        raise forms.ValidationError("File size must be under 10MB.")

    content_type = getattr(uploaded_file, "content_type", "")
    if content_type and content_type.lower() not in config["content_types"]:
        raise forms.ValidationError(
            f"Uploaded file content type must match {config['label']}."
        )

    header = _read_signature(uploaded_file)
    if not any(header.startswith(signature) for signature in config["signatures"]):
        raise forms.ValidationError(
            f"Uploaded file content does not match {config['label']}."
        )

    _scan_for_malware(uploaded_file)

    return uploaded_file
