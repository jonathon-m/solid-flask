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