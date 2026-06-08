from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import EntraJWTAuthentication
from .permissions import InternalAPIIsAuthenticated


class InternalAPIStatusView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    def get(self, request):
        return Response({'status': 'ok', 'version': 'v1'})
