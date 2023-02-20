# TODO(agentydragon): add logout

import json
import urllib

import flask
import jwcrypto
import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt
import requests
from absl import app, flags, logging
from solid_oidc import register_client, make_verifier_challenge, make_token_for, make_random_string, get_login_url, get_access_token
from storage import MemStore

_PORT = flags.DEFINE_integer('port', 3333, 'HTTP port to listen on')
_ISSUER = flags.DEFINE_string('issuer', 'https://solidcommunity.net/',
                              'Issuer')

_OID_CALLBACK_PATH = "/oauth/callback"


def get_redirect_url():
    return f"http://localhost:{_PORT.value}{_OID_CALLBACK_PATH}"


_TEMPLATE = """
<h2>Login status</h2>
{% if web_id %}
  You are logged in as {{ web_id }}.
{% else %}
  You are not logged in.
{% endif %}

<h2>Resource content</h2>
{% if resource %}
  <pre>{{ resource_content }}</pre>
{% else %}
  Use the form below to read a resource.
{% endif %}

<form action=/ method=GET>
  <input
      value="{{ resource }}"
      placeholder='https://you.solidcommunity.net/private/...'
      name='resource'>
  <input type=submit value=Read>
</form>
"""


def main(_):
    # Provider info discovery.
    # https://pyoidc.readthedocs.io/en/latest/examples/rp.html#provider-info-discovery
    provider_info = requests.get(_ISSUER.value +
                                 ".well-known/openid-configuration").json()
    logging.info("Provider info: %s", provider_info)
    client_id, client_secret = register_client(provider_info, get_redirect_url())

    flask_app = flask.Flask(__name__)
    flask_app.secret_key = 'notreallyverysecret123'

    # keyed by state, contains {'key': {...}, 'code_verifier': ...}
    STATE_STORAGE = MemStore()

    @flask_app.route('/')
    def index():
        tested_url = flask.request.args.get('resource', '')

        if ('access_token' in flask.session) and ('key' in flask.session):
            logging.info("loading access token and key from session")
            keypair = jwcrypto.jwk.JWK.from_json(flask.session['key'])
            access_token = flask.session['access_token']
            headers = {
                'Authorization': ('DPoP ' + access_token),
                'DPoP': make_token_for(keypair, tested_url, 'GET')
            }
            decoded_access_token = jwcrypto.jwt.JWT(jwt=access_token)
            # TODO(agentydragon): should we also verify the payload against
            # the signature it has?
            web_id = json.loads(
                decoded_access_token.token.objects['payload'])['sub']
            # TODO(agentydragon): if we pull the webid from here, it needs
            # further validation.
        else:
            headers = {}
            web_id = None

        if tested_url:
            # Read file from Solid.
            # TODO(agentydragon): handle token expiration, refreshes, etc.
            resp = requests.get(url=tested_url, headers=headers)
            if resp.status_code == 401:
                logging.info("Got 401 trying to access %s.", tested_url)
                code_verifier, code_challenge = make_verifier_challenge()

                state = make_random_string()
                assert not STATE_STORAGE.has(state)
                STATE_STORAGE.set(f'{state}_code_verifier', code_verifier)
                STATE_STORAGE.set(f'{state}_redirect_url', flask.request.url)

                url = get_login_url(code_challenge, state, get_redirect_url(), client_id, provider_info['authorization_endpoint'])
                return flask.redirect(url)
            elif resp.status_code != 200:
                raise Exception(
                    f"Unexpected status code: {resp.status_code} {resp.text}")

            resource_content = resp.text
        else:
            resource_content = None

        return flask.Response(flask.render_template_string(
            _TEMPLATE,
            web_id=web_id,
            resource_content=resource_content,
            resource=tested_url),
                              mimetype='text/html')

    @flask_app.route(_OID_CALLBACK_PATH)
    def oauth_callback():
        auth_code = flask.request.args['code']
        state = flask.request.args['state']
        assert STATE_STORAGE.has(f'{state}_code_verifier')

        # Generate a key-pair.
        keypair = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

        code_verifier = STATE_STORAGE.get(f'{state}_code_verifier')
        STATE_STORAGE.remove(f'{state}_code_verifier')

        access_token = get_access_token(
            token_endpoint=provider_info['token_endpoint'],
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=get_redirect_url(),
            code=auth_code,
            code_verifier=code_verifier,
            key=keypair,
        )

        flask.session['key'] = keypair.export()
        flask.session['access_token'] = access_token

        decoded_access_token = jwcrypto.jwt.JWT()
        decoded_access_token.deserialize(access_token)
        logging.info("access token: %s", decoded_access_token)

        redirect_url = STATE_STORAGE.get(f'{state}_redirect_url')
        STATE_STORAGE.remove(f'{state}_redirect_url')
        return flask.redirect(redirect_url)

    flask_app.run(port=_PORT.value, debug=True)


if __name__ == '__main__':
    app.run(main)
