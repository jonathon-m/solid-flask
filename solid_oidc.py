from typing import Optional
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oauth2.message import ASConfigurationResponse
import base64
import logging
import hashlib
import jwcrypto
import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt
import requests
import urllib.parse
from uuid import uuid4

from dpop_utils import make_token_for
from solid_auth_session import SolidAuthSession
from storage import KeyValueStore

class SolidOidcClient:
    def __init__(self, storage: KeyValueStore) -> None:
        self.client = OicClient(client_authn_method=CLIENT_AUTHN_METHOD)
        self.storage = storage
        self.provider_info: Optional[ASConfigurationResponse] = None 
        self.client_id: Optional[str] = None
        self.client_secret: Optional[str] = None

    def register_client(self, issuer: str, redirect_url: str):
        self.provider_info = self.client.provider_config(issuer)
        registration_response = self.client.register(
                self.provider_info['registration_endpoint'],
                redirect_uris=[redirect_url])
        logging.info("Registration response: %s", registration_response)
        self.client_id = registration_response['client_id']
        self.client_secret = registration_response['client_secret']

    def initialize_login(self, redirect_uri: str, callback_uri: str) -> str:
        authorization_endpoint = self.provider_info['authorization_endpoint']
        code_verifier, code_challenge = make_verifier_challenge()
        state = make_random_string()
        self.storage.set(f'{state}_code_verifier', code_verifier)
        self.storage.set(f'{state}_redirect_url', redirect_uri)
        args = {
            "code_challenge": code_challenge,
            "state": state,
            "response_type": "code",
            "redirect_uri": callback_uri,
            "code_challenge_method": "S256",
            "client_id": self.client_id,
            # TODO: should this be an option?
            # offline_access: also asks for refresh token
            "scope": "openid offline_access",
        }
        url = f'{authorization_endpoint}?{urllib.parse.urlencode(args)}'
        return url

    def finish_login(self, redirect_uri: str, code: str, state: str) -> str:
        key = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

        access_token = self._get_access_token(redirect_uri, code, state, key)

        return SolidAuthSession(access_token, key)
    
    def _get_access_token(self, redirect_uri: str, code: str, state: str, key: jwcrypto.jwk.JWK) -> str:
        token_endpoint = self.provider_info['token_endpoint']
        code_verifier = self.storage.get(f'{state}_code_verifier')

        res = requests.post(url=token_endpoint,
            auth=(self.client_id, self.client_secret),
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": code_verifier,
            },
            headers={
                'DPoP': make_token_for(key, token_endpoint, 'POST'),
            },
            allow_redirects=False)

        assert res.ok, f'Could not get access token: {res}'
        access_token = res.json()['access_token']
        self.storage.remove(f'{state}_code_verifier')

        return access_token

    def get_redirect_url(self, state: str) -> str:
        """Note: we never remove the redirect url from the storage"""
        return self.storage.get(f'{state}_redirect_url')


def make_random_string():
    return str(uuid4())


def make_verifier_challenge():
    code_verifier = make_random_string()

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_verifier, code_challenge