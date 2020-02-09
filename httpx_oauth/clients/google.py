from typing import Any, Dict, Tuple, cast, Optional

import httpx
from typing_extensions import Literal, TypedDict
from google.oauth2 import id_token
from google.auth.transport import requests

from httpx_oauth.errors import GetIdEmailError
from httpx_oauth.oauth2 import BaseOAuth2

AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
ACCESS_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_TOKEN_ENDPOINT = "https://accounts.google.com/o/oauth2/revoke"
BASE_SCOPES = [
    "openid",
    "email",
    "profile"
]
PROFILE_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"


class GoogleParsedIdToken(TypedDict, total=False):
    """ Decoded JWT. Optionals depend on scopes used to optain the token """
    iss: str
    azp: str
    aud: str
    sub: str
    email: Optional[str]
    email_verified: Optional[bool]
    name: Optional[str]


class GoogleOAuth2AuthorizeParams(TypedDict, total=False):
    access_type: Literal["online", "offline"]
    include_granted_scopes: bool
    login_hint: str
    prompt: Literal["none", "consent", "select_account"]


class GoogleOAuth2(BaseOAuth2[GoogleOAuth2AuthorizeParams]):
    def __init__(self, client_id: str, client_secret: str, name="google"):
        super().__init__(
            client_id,
            client_secret,
            AUTHORIZE_ENDPOINT,
            ACCESS_TOKEN_ENDPOINT,
            ACCESS_TOKEN_ENDPOINT,
            REVOKE_TOKEN_ENDPOINT,
            name=name,
            base_scopes=BASE_SCOPES,
        )

    def verify_oauth2_token(self, token: str) -> GoogleParsedIdToken:
        request = requests.Request()
        id_info = id_token.verify_oauth2_token(
            token, request, self.client_id)

        if id_info['iss'] != 'https://accounts.google.com':
            raise ValueError('Wrong issuer.')
        return GoogleParsedIdToken(**id_info)

    async def get_id_email(self, token: str) -> Tuple[str, str]:
        id_info = self.verify_oauth2_token(token=token)
        user_id = id_info['sub']
        user_email = id_info['email']
        user_verified = id_info['email_verified']

        return user_id, (user_email if user_verified else None)
