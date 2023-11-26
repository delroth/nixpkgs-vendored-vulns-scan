from rest_framework import serializers
from django.db import transaction
from django.db.models import Count
import json

from . import models


class VulnerablePackageSerializer(serializers.ModelSerializer):
    status = serializers.ReadOnlyField(source="get_status_display")

    class Meta:
        model = models.VulnerablePackage
        fields = ["id", "name", "status", "evaluation"]


class VulnerabilitySerializer(serializers.ModelSerializer):
    severity = serializers.ReadOnlyField(source="get_severity_display")
    status = serializers.ReadOnlyField(source="get_status_display")

    class Meta:
        model = models.Vulnerability
        fields = ["id", "first_seen", "last_seen", "severity", "status"]


class CreateEvaluationSerializer(serializers.ModelSerializer):
    result = serializers.FileField(write_only=True)

    class Meta:
        model = models.Evaluation
        fields = ["git_rev", "result"]

    def create(self, data):
        result = json.load(data.pop("result"))

        with transaction.atomic():
            evaluation = super().create(data)
            models.parse_scan_result(evaluation, result)
        return evaluation


class EvaluationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Evaluation
        fields = ["id", "git_rev"]
