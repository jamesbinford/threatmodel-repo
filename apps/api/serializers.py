from rest_framework import serializers


class InternalAPIStatusSerializer(serializers.Serializer):
    status = serializers.CharField()
    version = serializers.CharField()
