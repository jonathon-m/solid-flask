import datetime
import json
from uuid import uuid4
import jwcrypto
import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt

from dpop_utils import make_token_for

class SolidAuthSession:
    """Session of one logged in account"""
    def __init__(self, access_token: str, key: jwcrypto.jwk.JWK) -> None:
        self.access_token = access_token
        self.key = key

    def get_web_id(self) -> str:
        decoded_token = jwcrypto.jwt.JWT(jwt=self.access_token)
        payload = json.loads(decoded_token.token.objects['payload'])
        return payload['sub']

    def get_auth_headers(self, url: str, method: str) -> dict:
        """returns a dict of authentication headers for a target url and http method"""
        return {
            'Authorization': ('DPoP ' + self.access_token),
            'DPoP': make_token_for(self.key, url, method)
        }
    
    def serialize(self) -> str:
        """return a string representation of this session"""
        return json.dumps({
            'access_token': self.access_token,
            'key': self.key.export(),
        })
    
    @staticmethod
    def deserialize(serialization: str):
        obj = json.loads(serialization)
        access_token = obj['access_token']
        key = jwcrypto.jwk.JWK.from_json(obj['key'])
        return SolidAuthSession(access_token, key)

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
                               "jti": str(uuid4()),
                               "htm": method,
                               "htu": uri,
                               "iat": int(datetime.datetime.now().timestamp())
                           })
    jwt.make_signed_token(keypair)
    return jwt.serialize()