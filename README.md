# Solid Flask

A simple demo app to show how to use [solid_oidc_client](https://pypi.org/project/solid-oidc-client/0.0.2/). It is based on [solid-flask](https://gitlab.com/agentydragon/solid-flask/) by Rai. It runs a flask server that allows users to login and then fetches private resource through the credentials stored in the backend.

## Running

- Run `python3 -m venv venv` to create a virtual environment (so you don't install dependencies globally)
- Start the virtual environment, e.g. `. venv/bin/activate`
- Install dependencies `pip install -r requirements.txt`

Now you can start the application with `python solid_flask_main.py`. Append eg `--issuer https://login.inrupt.com/` to run it with a different issuer.
