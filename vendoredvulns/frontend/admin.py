from django.contrib import admin
from simple_history.admin import SimpleHistoryAdmin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.urls import reverse
from django.db import transaction
import sys

from . import models


class HistoryAdminMixin:
    history_list_display = ("list_changes",)

    def changed_fields(self, obj):
        if obj.prev_record:
            delta = obj.diff_against(obj.prev_record)
            return delta.changed_fields
        return None

    def list_changes(self, obj):
        fields = []
        if obj.prev_record:
            delta = obj.diff_against(obj.prev_record)
            for change in delta.changes:
                fields.append(
                    format_html(
                        "<strong>{}</strong>: <span"
                        " style='background-color:#ffb5ad'>{}</span> &rsaquo; <span"
                        " style='background-color:#b3f7ab'>{}</span><br/>",
                        change.field,
                        change.old,
                        change.new,
                    )
                )
            if not fields:
                return format_html("<em>no change</em>")
            return mark_safe("".join(fields))
        return ""


@admin.action(description="Update OSV data (one API call per vuln)")
def update_osv(modeladmin, request, queryset):
    with transaction.atomic():
        for vuln in queryset:
            vuln.update_osv()
            vuln.save()


class CanonicalXrefsInline(admin.TabularInline):
    model = models.Vulnerability
    verbose_name_plural = "Canonical x-refs"
    fields = ["__str__", "severity", "status", "summary"]
    readonly_fields = fields
    show_change_link = True
    extra = 0


class VulnerabilityAdmin(HistoryAdminMixin, SimpleHistoryAdmin):
    list_display = ["id", "severity", "status", "summary", "last_seen"]
    list_filter = ["severity", "status"]
    inlines = [CanonicalXrefsInline]
    actions = [update_osv]


class VulnerabilityThroughInline(admin.TabularInline):
    model = models.VulnerablePackage.vulnerabilities.through
    fields = ["vulnerability", "vulnerability_summary"]
    readonly_fields = fields
    extra = 0
    verbose_name_plural = "Vulnerabilities"

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("vulnerablepackage", "vulnerability")
        )

    def vulnerability_summary(self, obj):
        return obj.vulnerability.summary


class VulnerablePackageAdmin(HistoryAdminMixin, SimpleHistoryAdmin):
    list_display = ["name", "evaluation_link"]
    raw_id_fields = ["evaluation", "vulnerabilities"]
    inlines = [VulnerabilityThroughInline]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("evaluation")

    @admin.display(description="In evaluation", ordering="evaluation")
    def evaluation_link(self, obj):
        url = reverse("admin:frontend_evaluation_change", args=[obj.evaluation.id])
        return format_html('<a href="{}">{}</a>', url, obj.evaluation)


class PackagesInline(admin.TabularInline):
    model = models.VulnerablePackage
    fields = ["name", "status"]
    readonly_fields = ["name"]
    show_change_link = True
    extra = 0


class EvaluationAdmin(admin.ModelAdmin):
    list_display = ["id", "git_rev_link", "added"]
    inlines = [PackagesInline]

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("packages")

    @admin.display(description="Git revision", ordering="git_rev")
    def git_rev_link(self, obj):
        url = f"https://github.com/NixOS/nixpkgs/commit/{obj.git_rev}"
        return format_html('<a href="{}"><code>{}</code></a>', url, obj.short_git_rev)


admin.site.register(models.Vulnerability, VulnerabilityAdmin)
admin.site.register(models.VulnerablePackage, VulnerablePackageAdmin)
admin.site.register(models.Evaluation, EvaluationAdmin)
