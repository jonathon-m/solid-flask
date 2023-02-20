# About

This is a fork of [solid-flask](https://gitlab.com/agentydragon/solid-flask/) by Rai. I've refactored the authentication logic to be more reusable.

# solid-flask

This is a simple Flask app that can authenticate against a Solid pod and read
private data from it.

It should become simpler when [Demonstration of
Proof-of-Possession](https://tools.ietf.org/html/draft-fett-oauth-dpop-04) gets
implemented in some Python OAuth library. Unfortunately, as of time of writing,
I can't find a Python library that implements DPoP, and Solid seems to require
it.

## Running

- Run `python3 -m venv vev` to create a virtual environment (so you don't install dependencies globally)
- Start the virtual environment, e.g. `. venv/bin/activate`
- Install dependencies `pip install -r requirements.txt`

Now you can start the application with `python solid_flask_main.py`. Append eg `--issuer https://login.inrupt.com/` to run it with a different issuer.

## Authentication Flow

Following code guides you through the authentication process:

```python
from solid_oidc import SolidOidcClient
from solid_auth_session import SolidAuthSession
from storage import MemStore

# create a client instance
solid_oidc_client = SolidOidcClient(storage=MemStore())
OAUTH_CALLBACK_URI = '/oauth/callback'

# register this application with the issuer (client_id and client_secret are currently only stored in memory, regardless of the previous storage)
# the redirect url in this case is /oauth/callback
solid_oidc_client.register_client('https://login.inrupt.com/', [OAUTH_CALLBACK_URI])

# initiate a login by redirecting the user to this url
# store the path you want to redirect the user after the login ('/')
login_url = solid_oidc_client.create_login_uri('/', OAUTH_CALLBACK_URI)

# wait for the user to login with their identity provider
# listen on /oauth/callback
# then get code and state from the query params
code = flask.request.args['code']
state = flask.request.args['state']

# and use them to get an authentication session
# internally this will store an access token and key for dpop
session = solid_oidc_client.finish_login(
    code=code,
    state=state,
    callback_uri=OAUTH_CALLBACK_URI,
)

# use this session to make authenticated requests
private_url = 'https://pod.example.org/private/secret.txt'
auth_headers = session.get_auth_headers(private_url, 'GET')
res = requests.get(url=tested_url, headers=auth_headers)
print(res.text)


# optionally serialize and deserialize the sessions to store them as a string client/server side
flask.session['auth'] = session.serialize()
session = SolidAuthSession.deserialize(flask.session['auth'])
```

## TODOs

- [ ] persist client id and secret
- [ ] refresh tokens when they expire