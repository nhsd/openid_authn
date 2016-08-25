from flask import Flask, request, render_template, session, redirect, current_app, g
from urllib.request import urlopen
from urllib.parse import urlencode
import random
import json
import os, requests
from functools import wraps
import logging
from storage import redisclient
import hmac
import hashlib
import base64
import pyjwt

app = Flask(__name__)

if 'REDIS_PORT' in os.environ:
    redis_addr = os.environ['REDIS_PORT']
else:
    redis_addr = 'tcp://localhost:6379'

redis_port = redis_addr.split(':')[2]
redis_ip = redis_addr.split('//')[1].split(':')[0]

redisclient(redis_ip, redis_port)

log = logging.getLogger('view')


@app.before_request
def log_request():
    g.transaction_id = random.randint(0, 100000)
    log.info('Method=BeforeRequest Transaction=%s URL=%s ClientIP=%s Method=%s Proto=%s UserAgent=%s'
             % (g.transaction_id,
                request.url,
                request.headers.environ['REMOTE_ADDR'],
                request.headers.environ['REQUEST_METHOD'],
                request.headers.environ['SERVER_PROTOCOL'],
                request.headers.environ['HTTP_USER_AGENT']))


@app.route('/test/<param>')
def test(param):
    key_name = 'test_value'
    redisclient.set(key_name, param)
    persisted_value = redisclient.get(key_name)
    return "OK %s" % persisted_value


@app.route('/authorize')
def login():
    (valid, reason) = _is_valid_authorize_request(request)
    if not valid:
        if reason == 'no_redirect_uri':
            return reason, 400

        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')

        if reason == 'unknown_client' or reason == 'invalid_redirect_uri':
            # TODO: inform user of what happened.
            reason = 'access_denied'

        uri = redirect_uri + '?' + 'error=' + reason
        if state is not None:
            uri += '&state=' + state
        return redirect(uri, code=302)
    return render_template('login.html')


@app.route('/credentialsSubmitted/')
def submit_credentials():
    return render_template('auth_page.html')


@app.route('/token')
def token_callback():
    authorization_string = request.headers.Authorization
    decoded_authorization_string = decode_authorization_header(authorization_string)

    client_id = decoded_authorization_string.header.clientID
    secret = decoded_authorization_string.header.secret

    grant_type_param = request.args.get('grant_type')
    code_param = request.args.get('code')
    redirect_uri_param = request.args.get('redirect_uri')

    token = get_token_header() + '.' + get_token()

    encoded_token = encode_token(token)
    response = {'id_token': encoded_token,
                "access_token": "SlAV32hkKG",
                "token_type": "Bearer",
                "expires_in": 3600}

    json_response = json.dumps(response)
    return json_response


def _is_valid_authorize_request(request):
    if len(request.args) > 5:
        return False, "invalid_request"

    response_type = request.args.get('response_type')
    scope = request.args.get('scope')
    client_id = request.args.get('client_id')
    state = request.args.get('state')
    redirect_uri = request.args.get('redirect_uri')

    if redirect_uri is None:
        return False, 'no_redirect_uri'

    if response_type is None or scope is None or client_id is None or state is None:
        return False, "invalid_request"
    if response_type != 'code':
        return False, 'unsupported_response_type'

    if scope != 'openid':
        return False, "invalid_scope"

    # TODO: Get client info from redis
    client_info = _get_client_info(client_id)

    if client_info is None:
        return False, 'unknown_client'

    if redirect_uri != client_info['redirect_uri']:
        return False, 'invalid_redirect_uri'

    return True, ''


def _get_client_info(client_id):
    if client_id == "example":
        return {'client_id': 'example', 'redirect_uri': 'https://client.example.org/cb'}
    return None


# Stub method - to be replaced with the proper one that Matt writes
def get_token(user_id, client_id):
    from datetime import datetime
    ret = {'iss': 'https://dummy.co/stuff', 'sub': user_id, 'aud': client_id,
           'exp': int(datetime.now().strftime("%s")) + 600, 'iat': int(datetime.now().strftime("%s"))}

    return encode_token(json.dumps(ret))

def get_token_header():

    header = {"alg": "HS256", "typ": "JWT"}

    return encode_token(json.dumps(header))

def decode_authorization_header(authorization_string):
    return base64.b64decode(authorization_string)


def encode_token(token):
    return base64.b64encode(token)


private_key="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"
