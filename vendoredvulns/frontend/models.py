from django.db import models
from django.core.exceptions import ValidationError
from simple_history.models import HistoricalRecords
from django.core.validators import RegexValidator
import urllib3


def _osv_link(kind: str):
    def getter(self: "Vulnerability"):
        try:
            return next(
                (ref["url"] for ref in self.osv["references"] if ref["type"] == kind)
            )
        except:
            return

    return property(getter)


def _osv_field(key: str):
    def getter(self: "Vulnerability"):
        try:
            return str(self.osv.get(key, None))
        except:
            return

    return property(getter)


def parse_scan_result(evaluation: "Evaluation", data: dict):
    """Parses a scan JSON result, creating all unseen vulnerabilities."""

    packages = []
    vulns = {}
    for package_name, result in data.items():
        if not result["success"]:
            continue

        package = VulnerablePackage(name=package_name, evaluation=evaluation)
        packages.append(package)

        for vuln in result["vulns"]:
            vulns[vuln["id"]] = Vulnerability(id=vuln["id"])

    packages = VulnerablePackage.objects.bulk_create(packages)
    vulns = Vulnerability.objects.bulk_create(
        vulns.values(),
        update_conflicts=True,
        update_fields=["last_seen"],
        unique_fields=["id"],
    )
    VulnToPackage = VulnerablePackage.vulnerabilities.through
    VulnToPackage.objects.bulk_create([
        VulnToPackage(vulnerability=vuln, vulnerablepackage=package)
        for package in packages
        for vuln in vulns
    ])
    return packages, vulns


class Evaluation(models.Model):
    """A run of the vulnerability scanner at a specific nixpkgs git revision."""

    # Added timestamp.
    added = models.DateTimeField(auto_now_add=True)
    # nixpkgs git revision.
    git_rev = models.CharField(
        max_length=64, validators=[RegexValidator(r"^[a-f0-9]{40}$")]
    )

    @property
    def short_git_rev(self):
        return self.git_rev[:7]

    def __str__(self):
        return f"{self.short_git_rev} on {self.added}"

    class Meta:
        ordering = ("-added",)


class Vulnerability(models.Model):
    """A unique vulnerability and associated metadata."""

    class Severity(models.IntegerChoices):
        UNSET = 0, "Unset"
        NEGLIGIBLE = 1, "Negligible"
        MINOR = 2, "Minor"
        MAJOR = 3, "Major"
        HUGE = 4, "Huge"

    class Status(models.IntegerChoices):
        NEW = 0, "New"
        TRIAGED = 1, "Triaged"
        RESOLVED = 2, "Resolved"
        OBSOLETE = 3, "Obsolete"

    id = models.CharField(max_length=128, unique=True, primary_key=True)
    # First & last seen timestamps.
    first_seen = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen = models.DateTimeField(auto_now=True, db_index=True)
    # Manual severity level.
    severity = models.IntegerField(
        choices=Severity.choices, default=Severity.UNSET, db_index=True
    )
    # Action-taking status.
    status = models.IntegerField(
        choices=Status.choices, default=Status.NEW, db_index=True
    )
    # Canonical vulnerability, for deduplication purposes. Optional.
    canonical = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, db_index=True
    )
    # Local copy of the vulnerability metadata from https://osv.dev.
    osv = models.JSONField(null=True, blank=True)
    # Change tracking.
    history = HistoricalRecords(
        cascade_delete_history=True,
        excluded_fields=["osv", "first_seen", "last_seen"],
    )

    # Convenience shortcuts.
    summary = _osv_field("summary")
    link_advisory = _osv_link("ADVISORY")
    link_detection = _osv_link("DETECTION")
    link_report = _osv_link("REPORT")
    link_fix = _osv_link("FIX")

    def __str__(self):
        return self.id

    def clean(self):
        if self.id is None:
            return
        parent = self.canonical
        while parent is not None:
            if parent.id == self.id:
                raise ValidationError("Canonical cannot be self-referential")
            parent = parent.canonical

    def update_osv(self):
        if not self.id:
            return ValueError("Vulnerability.id is empty or None")
        self.osv = urllib3.request(
            "GET", f"https://api.osv.dev/v1/vulns/{self.id}"
        ).json()

    @classmethod
    def from_osv(cls, osv_id: str):
        vuln = cls(id=osv["id"])
        vuln.update_osv()
        return vuln

    class Meta:
        ordering = ("-last_seen",)


class VulnerablePackage(models.Model):
    """A vulnerable package found by a scanner evaluation."""

    class Status(models.IntegerChoices):
        NEW = 0, "New"
        TRIAGED = 1, "Triaged"
        RESOLVED = 2, "Resolved"
        OBSOLETE = 3, "Obsolete"

    # Nixpkgs package name.
    name = models.CharField(max_length=255, db_index=True, blank=False)
    # What vulnerabilities were found affecting this package.
    vulnerabilities = models.ManyToManyField(Vulnerability, related_name="packages")
    # Which evaluation discovered this vulnerable package.
    evaluation = models.ForeignKey(
        Evaluation, on_delete=models.SET_NULL, null=True, related_name="packages"
    )
    # Action-taking status.
    status = models.IntegerField(choices=Status.choices, default=0, db_index=True)
    # Change tracking.
    history = HistoricalRecords(
        cascade_delete_history=True,
        excluded_fields=["name", "vulnerabilities", "evaluation"],
    )

    def __str__(self):
        return self.name
