import sys
import hmac

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework import authentication
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied, BadRequest, PermissionDenied

import cachetools.func
import github


GITHUB_ORG = "NixOS"  # https://github.com/NixOS
GITHUB_TEAM_ID = 2197543  # https://github.com/orgs/NixOS/teams/security


class NoSignupAccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        return False


@cachetools.func.ttl_cache(ttl=10 * 60)
def allowed_user_ids():
    """Extracts a GitHub team members, plus configured allowlisted, minus denylisted."""

    gh = github.Github(auth=github.Auth.Token(settings.GITHUB_API_TOKEN))
    members = gh.get_organization(GITHUB_ORG).get_team(GITHUB_TEAM_ID).get_members()
    members = {m.id for m in members}
    return (members | settings.GITHUB_EXTRA_USERS) - settings.GITHUB_DENYLISTED_USERS


def is_allowed_user_id(extra_data: dict):
    return extra_data["id"] in allowed_user_ids()


class GithubTeamSocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, sociallogin):
        return True

    def pre_social_login(self, request, sociallogin):
        if not is_allowed_user_id(sociallogin.account.extra_data):
            raise PermissionDenied


class ApiUser(AnonymousUser):
    """A fake user for the API endpoints."""

    @property
    def is_authenticated(self):
        return True


class TokenDRFAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        try:
            literal, token = request.META.get("HTTP_AUTHORIZATION", "").split()
        except ValueError:
            raise PermissionDenied
        if literal.lower() != "token":
            raise PermissionDenied
        if not hmac.compare_digest(token, settings.API_SECRET_TOKEN):
            raise PermissionDenied
        return (ApiUser(), None)
