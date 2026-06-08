import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .models import InternalAPIClient


class EntraJWTAuthentication(BaseAuthentication):
    """Authenticates internal API callers using Microsoft Entra access tokens."""
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        token = self.get_bearer_token(request)
        if token is None:
            return None

        claims = self.decode_token(token)
        self.validate_claims(claims)

        client = InternalAPIClient.active_for_claims(
            app_id=claims.get('appid') or claims.get('azp'),
            object_id=claims.get('oid'),
        )
        if client is None:
            raise AuthenticationFailed('Unknown or inactive API client.')

        client.mark_used()
        request.internal_api_client = client
        return client.user, client

    def authenticate_header(self, request):
        return f'Bearer realm="{self.www_authenticate_realm}"'

    def get_bearer_token(self, request):
        auth = get_authorization_header(request).split()
        if not auth:
            return None
        if auth[0].lower() != b'bearer':
            raise AuthenticationFailed('Authorization header must use Bearer authentication.')
        if len(auth) != 2:
            raise AuthenticationFailed('Invalid bearer token header.')
        return auth[1].decode('utf-8')

    def decode_token(self, token):
        try:
            signing_key = self.get_signing_key(token)
            return jwt.decode(
                token,
                signing_key,
                algorithms=['RS256'],
                audience=settings.ENTRA_AUDIENCE,
                issuer=settings.ENTRA_ISSUER,
                options={'require': ['exp', 'iss', 'aud']},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationFailed('Invalid Entra access token.') from exc

    def get_signing_key(self, token):
        test_key = getattr(settings, 'ENTRA_TEST_PUBLIC_KEY', None)
        if test_key:
            return test_key
        if not settings.ENTRA_JWKS_URL:
            raise AuthenticationFailed('Entra JWKS URL is not configured.')
        return jwt.PyJWKClient(settings.ENTRA_JWKS_URL).get_signing_key_from_jwt(token).key

    def validate_claims(self, claims):
        tenant_id = getattr(settings, 'ENTRA_TENANT_ID', '')
        if tenant_id and claims.get('tid') != tenant_id:
            raise AuthenticationFailed('Token tenant is not allowed.')

        roles = set(claims.get('roles') or [])
        required_roles = set(getattr(settings, 'ENTRA_REQUIRED_ROLES', []))
        if required_roles and roles.isdisjoint(required_roles):
            raise AuthenticationFailed('Token is missing a required application role.')

        if not (claims.get('appid') or claims.get('azp')):
            raise AuthenticationFailed('Token is missing caller application ID.')
        if not claims.get('oid'):
            raise AuthenticationFailed('Token is missing caller object ID.')
