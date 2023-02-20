from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
import datetime
import base64
import logging
import hashlib
import os
import re
import jwcrypto
import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt
import requests
import urllib.parse

# TODO reusing a client expects to use the same OP
# see NOTE at https://pyoidc.readthedocs.io/en/latest/examples/rp.html#client-registration
client = OicClient(client_authn_method=CLIENT_AUTHN_METHOD)

def register_client(provider_info, redirect_url: str):
    # Client registration.
    # https://pyoidc.readthedocs.io/en/latest/examples/rp.html#client-registration
    registration_response = client.register(
            provider_info['registration_endpoint'],
            redirect_uris=[redirect_url])
    logging.info("Registration response: %s", registration_response)
    return registration_response['client_id'], registration_response['client_secret']

def make_random_string():
    x = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    x = re.sub('[^a-zA-Z0-9]+', '', x)
    return x


def make_verifier_challenge():
    code_verifier = make_random_string()

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_verifier, code_challenge


def make_token_for(keypair, uri, method):
    jwt = jwcrypto.jwt.JWT(header={
        "typ":
        "dpop+jwt",
        "alg":
        "ES256",
        "jwk":
        keypair.export(private_key=False, as_dict=True)
    },
                           claims={
                               "jti": make_random_string(),
                               "htm": method,
                               "htu": uri,
                               "iat": int(datetime.datetime.now().timestamp())
                           })
    jwt.make_signed_token(keypair)
    return jwt.serialize()

def get_login_url(code_challenge: str, state: str, redirect_uri: str, client_id: str, authorization_endpoint: str) -> str:
    args = {
        "code_challenge": code_challenge,
        "state": state,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge_method": "S256",
        "client_id": client_id,
        # offline_access: also asks for refresh token
        "scope": "openid offline_access",
    }
    url = f'{authorization_endpoint}?{urllib.parse.urlencode(args)}'
    return url

def get_access_token(token_endpoint: str, client_id: str, client_secret: str, redirect_uri: str, code: str, code_verifier: str, key: jwcrypto.jwk.JWK) -> str:
    resp = requests.post(url=token_endpoint,
                        auth=(client_id, client_secret),
                        data={
                            "grant_type": "authorization_code",
                            "client_id": client_id,
                            "redirect_uri": redirect_uri,
                            "code": code,
                            "code_verifier": code_verifier,
                        },
                        headers={
                            'DPoP':
                            make_token_for(
                                key, token_endpoint,
                                'POST')
                        },
                        allow_redirects=False)
    result = resp.json()
    logging.info("%s", result)
    return result['access_token']
