from django.http import HttpResponse
from django.views import View
from rest_framework import generics, status
from rest_framework.response import Response as RestResponse

from . import models
from .auth import TokenDRFAuthentication
from .serializers import (
    CreateEvaluationSerializer,
    EvaluationSerializer,
    VulnerabilitySerializer,
    VulnerablePackageSerializer,
)


class ApiPostScanResult(generics.CreateAPIView):
    """Parses a scan JSON result.

    Typical usage:
        $ curl example.org/api/v1/scan/result -H 'Authorization: Token changeme' \
            -F result=@result.json -F git_rev=86fb21cde5d4c89fa3f10a77a79c6e46b45ff478
    """

    authentication_classes = [TokenDRFAuthentication]

    def create(self, request, *args, **kwargs):
        serializer = CreateEvaluationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        evaluation = serializer.save()
        return RestResponse(
            {
                "evaluation": EvaluationSerializer(evaluation).data,
                "packages": VulnerablePackageSerializer(
                    evaluation.packages.all(), many=True
                ).data,
                "vulnerabilities": VulnerabilitySerializer(
                    models.Vulnerability.objects.filter(
                        packages__in=evaluation.packages.all().values("id")
                    ),
                    many=True,
                ).data,
            },
            status=status.HTTP_201_CREATED,
            headers=self.get_success_headers(serializer.data),
        )


class Home(View):
    def get(self, request):
        v = models.Vulnerability.objects.count()
        p = models.VulnerablePackage.objects.count()
        return HttpResponse(
            f"Hello, world! I know about {v} vulnerabilities in {p} packages."
        )
