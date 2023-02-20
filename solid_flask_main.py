import flask
import requests
from absl import app, flags

from solid_oidc_client import SolidOidcClient, SolidAuthSession, MemStore

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
  <form action=/logout method=POST>
    <button type="submit">Logout</button>
  </form>

  <h2>Fetch files</h2>
  <form action=/ method=GET>
  <input
      value="{{ resource }}"
      placeholder='https://you.solidcommunity.net/private/...'
      name='resource'>
  <input type=submit value=Read>
  </form>

  {% if resource %}
  <h2>Resource content</h2>
  <pre>{{ resource_content }}</pre>
  {% endif %}

{% else %}
  You are not logged in.
  <form action=/login method=POST>
    <button type="submit">Login</button>
  </form>
{% endif %}
"""


def main(_):
    solid_oidc_client = SolidOidcClient(storage=MemStore())
    solid_oidc_client.register_client(str(_ISSUER.value), [get_redirect_url()])

    flask_app = flask.Flask(__name__)
    flask_app.secret_key = 'notreallyverysecret123'

    @flask_app.route('/')
    def index():
        tested_url = flask.request.args.get('resource', '')

        if 'auth' in flask.session:
            session = SolidAuthSession.deserialize(flask.session['auth'])
            headers = session.get_auth_headers(tested_url, 'GET')
            web_id = session.get_web_id()
        else:
            headers = {}
            web_id = None

        if tested_url:
            res = requests.get(url=tested_url, headers=headers)
            resource_content = res.text
        else:
            resource_content = None

        return flask.Response(flask.render_template_string(
            _TEMPLATE,
            web_id=web_id,
            resource_content=resource_content,
            resource=tested_url),
                              mimetype='text/html')
    
    @flask_app.route('/login', methods=['POST'])
    def login():
        login_url = solid_oidc_client.create_login_uri('/', get_redirect_url())
        return flask.redirect(login_url)
    
    @flask_app.route('/logout', methods=['POST'])
    def logout():
        flask.session.clear()
        return flask.redirect('/')


    @flask_app.route(_OID_CALLBACK_PATH)
    def oauth_callback():
        code = flask.request.args['code']
        state = flask.request.args['state']

        session = solid_oidc_client.finish_login(
            code=code,
            state=state,
            callback_uri=get_redirect_url(),
        )

        flask.session['auth'] = session.serialize()

        redirect_url = solid_oidc_client.get_application_redirect_uri(state)
        return flask.redirect(redirect_url)

    flask_app.run(port=_PORT.value, debug=True)


if __name__ == '__main__':
    app.run(main)
