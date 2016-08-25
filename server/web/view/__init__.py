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




    request_headers = dict([("client_id", client_id), ("secret", secret)])
    request_parameters = dict([("grant_type", grant_type_param), ("code", code_param), ("redirect_uri", redirect_uri_param)])
    request_signature = dict([])

    token = dict([('sub', "alice"), ('iss', "https://openid.c2id.com"),
                  ('aud', client_id), ('auth_time', 1311280969), ('acr', "c2id.loa.hisec"), ('iat', 1311280970),
                  ('exp', 1311281970)])

    encoded_token = encode_token(token)
    response =    {'id_token': encoded_token,
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

    #TODO: Get client info from redis
    client_info = _get_client_info(client_id)

    if client_info is None:
        return False, 'unknown_client'

    if redirect_uri != client_info['redirect_uri']:
        return False, 'invalid_redirect_uri'

    return True, ''

def _get_client_info(client_id):
    if client_id == "example":
        return { 'client_id': 'example', 'redirect_uri': 'https://client.example.org/cb' }
    return None

# Stub method - to be replaced with the proper one that Matt writes
def get_token(session_id):
    from datetime import datetime
    ret = {'iss': 'https://dummy.co/stuff', 'sub': '01234567', 'aud': '', 'exp': int(datetime.now().strftime("%s")) + 600, 'iat': int(datetime.now().strftime("%s"))}

    return json.dumps(ret)

def decode_authorization_header(authorization_string):
    return base64.b64decode(authorization_string)


def encode_token(token):
    return base64.b64encode(token)
