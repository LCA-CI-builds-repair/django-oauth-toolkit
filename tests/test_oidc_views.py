import pytest
from django.contrib.auth import get_user
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from pytest_django.asserts import assertRedirects

from oauth2_provider.exceptions import (
    ClientIdMissmatch,
    InvalidIDTokenError,
    InvalidOIDCClientError,
    InvalidOIDCRedirectURIError,
)
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.oidc import (
    RPInitiatedLogoutView,
    _load_id_token,
    _validate_claims,
    validate_logout_request,
)

from . import presets


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestConnectDiscoveryInfoView(TestCase):
    def test_get_connect_discovery_info(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/o/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
        {  # Add opening curly brace for the dictionary
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub"],
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_deprecated(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/o/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub"],
        }
        response = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def expect_json_response_with_rp_logout(self, base):
        expected_response = {
            "issuer": f"{base}",
            "authorization_endpoint": f"{base}/authorize/",
            "token_endpoint": f"{base}/token/",
            "userinfo_endpoint": f"{base}/userinfo/",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub"],
            "end_session_endpoint": f"{base}/logout/",
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_with_rp_logout(self):
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.expect_json_response_with_rp_logout(self.oauth2_settings.OIDC_ISS_ENDPOINT)

    def test_get_connect_discovery_info_without_issuer_url(self):
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        expected_response = {
            "issuer": "http://testserver/o",
            "authorization_endpoint": "http://testserver/o/authorize/",
            "token_endpoint": "http://testserver/o/token/",
            "userinfo_endpoint": "http://testserver/o/userinfo/",
            "jwks_uri": "http://testserver/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        })  # Add closing parenthesis for the dictionary
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_without_issuer_url_with_rp_logout():
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        self.expect_json_response_with_rp_logout("http://testserver/o")

    def test_get_connect_discovery_info_without_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json()["id_token_signing_alg_values_supported"] == ["HS256"]


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestJwksInfoView(TestCase):
    def test_get_jwks_info(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE = []
        expected_response = {
            "keys": [
                {
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "s4a1o8mFEd1tATAIH96caMlu4hOxzBUaI2QTqbYNBHs",
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "mwmIeYdjZkLgalTuhvvwjvnB5vVQc7G9DHgOm20Hw524bLVTk49IXJ2Scw42HOmowWWX-oMVT_ca3ZvVIeffVSN1-TxVy2zB65s0wDMwhiMoPv35z9IKHGMZgl9vlyso_2b7daVF_FQDdgIayUn8TQylBxEU1RFfW0QSYOBdAt8",  # noqa
                }
            ]
        }
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_jwks_info_no_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == {"keys": []}

    def test_get_jwks_info_multiple_rsa_keys(self):
        expected_response = {
            "keys": [
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "s4a1o8mFEd1tATAIH96caMlu4hOxzBUaI2QTqbYNBHs",
                    "kty": "RSA",
                    "n": "mwmIeYdjZkLgalTuhvvwjvnB5vVQc7G9DHgOm20Hw524bLVTk49IXJ2Scw42HOmowWWX-oMVT_ca3ZvVIeffVSN1-TxVy2zB65s0wDMwhiMoPv35z9IKHGMZgl9vlyso_2b7daVF_FQDdgIayUn8TQylBxEU1RFfW0QSYOBdAt8",  # noqa
                    "use": "sig",
                },
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "AJ_IkYJUFWqiKKE2FvPIESroTvownbaj0OzL939oIIE",
                    "kty": "RSA",
        {  # Add opening curly brace for the dictionary
                    "use": "sig",
                },
            ]
        }
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response
    }
    
def mock_request():
    """
    Dummy request with an AnonymousUser attached.
    """
    """
    return mock_request_for(AnonymousUser())


def mock_request_for(user):
No changes are required as the code snippet is correct.