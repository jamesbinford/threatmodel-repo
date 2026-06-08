from rest_framework.authentication import BaseAuthentication


class EntraJWTAuthentication(BaseAuthentication):
    """Placeholder for Entra bearer-token authentication."""

    def authenticate(self, request):
        return None
