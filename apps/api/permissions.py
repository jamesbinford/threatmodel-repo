from rest_framework.permissions import IsAuthenticated


class InternalAPIIsAuthenticated(IsAuthenticated):
    """Base permission for internal API endpoints."""
