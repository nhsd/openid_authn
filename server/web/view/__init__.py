from flask import Flask, request, render_template, redirect, g, Response
import random
import json
import os, requests
import logging
from storage import redisclient
import base64
import socket
from datetime import datetime
from jose import jwt

app = Flask(__name__)

if 'REDIS_PORT' in os.environ:
    redis_addr = os.environ['REDIS_PORT']
else:
    redis_addr = 'tcp://localhost:6379'

redis_port = redis_addr.split(':')[2]
redis_ip = redis_addr.split('//')[1].split(':')[0]

redisclient(redis_ip, redis_port)

log = logging.getLogger('view')

scope_map = { "openid": "Use your NHS login to sign you in",
              "email": "View your email address" }


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


@app.route('/authorize', methods=['GET'])
def login():
    (valid, reason, client_info) = _is_valid_authorize_request(request)
    if not valid:
        if reason == 'no_redirect_uri':
            return render_template('error.html', \
                                   message="The client you have come from is not properly configured. Please go back.")

        uri = client_info['redirect_uri'] + '?'
        if client_info['state'] is not None:
            uri += 'state=' + client_info['state'] + '&'

        if reason == 'unknown_client' or reason == 'invalid_redirect_uri':
            return render_template('error.html', \
                                   message="You've come from a client we don't recognise so we can't sign you in.", \
                                   redirect=[uri + 'error=access_denied'])
        uri += 'error=' + reason
        return redirect(uri, code=302)
    return render_template('login.html', errorMessage="", client_info=client_info)


@app.route('/authorize', methods=['POST'])
def submit_credentials():
    stored_password = redisclient.hget(request.form['user'], 'password')
    entered_password = request.form['passw']

    print(request.form['client_info'])

    client_info = json.loads(request.form['client_info'].replace('\'', '"'))

    if stored_password == entered_password:
        scopes = []
        for scope in client_info['scope'].split(" "):
            scopes.append(scope_map[scope])
        return render_template('auth_page.html', client_info = client_info, scopes = scopes, user_id = request.form['user'])
    else:
        return render_template('login.html', errorMessage="Incorrect username or password.", client_info=client_info)


@app.route('/authorisationSubmitted', methods=['POST'])
def auth_submit():
    authResponse = request.form['auth']

    client_info = json.loads(request.form['client_info'].replace('\'', '"'))

    if authResponse == "Cancel":
        return redirect(client_info['redirect_uri'] + '?error=access_denied&state=' + client_info['state'], code=302)

    token = generate_authorisation_token(client_info)

    return redirect(client_info['redirect_uri'] + '?code=' + token + '&state=' + client_info['state'])

secret = 'fd2q9VmSZZW2QKz5PhLP'


def generate_authorisation_token(client_info):

    time = int(datetime.now().timestamp())

    claims = {"sub": client_info['client_id'],
              "iss": socket.gethostname(),
              "iat": time,
              'aud': socket.gethostname(),
              "exp": time + 30,
              "scp": client_info['scope'],
              "amr": "password"}

    token = jwt.encode(claims, secret, algorithm='HS256')

    return token


@app.route('/token', methods=['POST'])
def token_callback():
    #if not _is_valid_token_request(request):
    #    return requests.Response.raise_for_status()

    # authorization_string = request.headers.Authorization
    # decoded_authorization_string = decode_base64encoded_dict(authorization_string)
    #
    # client_id = decoded_authorization_string.header.clientID
    # secret = decoded_authorization_string.header.secret

    grant_type_param = request.args.get('grant_type')
    code_param = request.args.get('code')
    redirect_uri_param = request.args.get('redirect_uri')

    (valid, reason, data) = _is_valid_token_request(request)
    if not valid:
        return 'ERROR'

    (valid, reason) = _is_valid_token_payload(data['claims'])
    if not valid:
        print(reason)
        return requests.Response.raise_for_status()

    time = int(datetime.now().timestamp())
    claims = { 'sub': data['client_id'],
               'iss': socket.gethostname(),
               'aud': data['client_id'],
               'jti': '3utwh54n9',
               'iat': time,
               'amr': data['claims']['amr'], #TODO: standards?
               'exp': time + 600 }

    token = jwt.encode(claims, secret, algorithm='HS256')

    response = {'id_token': token,
                "access_token": "SlAV32hkKG",
                "token_type": "Bearer",
                "expires_in": 3600}

    json_response = json.dumps(response)

    resp = Response(json_response)
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Cache-Control'] = 'no-cache, no-store'
    resp.headers['Pragma'] = 'no-cache'

    return resp


def _is_valid_token_payload(payload):
    expected_fields = ['iss', 'sub', 'aud', 'exp', 'iat']
    # raw_returned_token = view.get_token('158616253415', '731983621552')
    # decoded_token = base64.b64decode(payload)
    # returned_token = json.loads(decoded_token.decode('utf-8'))

    expected_min_iat_time = int(datetime.now().timestamp()) - 50
    expected_max_iat_time = expected_min_iat_time + 50
    expected_min_exp_time = expected_min_iat_time + 600  # Assumes 10 minute token lifetime
    expected_max_exp_time = expected_min_exp_time + 10

    # for field in expected_fields:
    #     if field not in payload:
    #         return False, "missing field"
    # if payload['iat'] < expected_min_iat_time or payload['iat'] < expected_max_iat_time:
    #     return False, "issued at time"
    # if payload['exp'] < expected_min_exp_time or payload['exp'] < expected_max_exp_time:
    #     return False, "expiry time"
    return True, None


def _is_valid_token_request(request):

    print(len(request.args))

    if len(request.args) != 3:
        return False, "3 Requests params expected (grant_type, code and redirect_uri)", None

    content_type = request.headers['Content-Type']
    authorization_header = request.headers['Authorization'].split('Basic ')[1]

    [client_id, client_secret] = base64.b64decode(authorization_header).decode('utf-8').split(':')

    grant_type = request.args.get('grant_type')
    code = request.args.get('code')
    redirect_uri = request.args.get('redirect_uri')

    if grant_type is None or grant_type != 'authorization_code':
        return False, " grant_type must be authorization_code", None

    if code is None:
        return False, "code param must be supplied", None

    (valid_code, claims) = validate_code(code)
    if not valid_code:
        return False, "invalid code", None

    if redirect_uri is None or redirect_uri == '':
        return False, 'no_redirect_uri', None

    if content_type is None or content_type != 'application/x-www-form-urlencoded':
        return False, 'content type must be application/x-www-form-urlencoded', None

    if authorization_header is None:
        return False, 'authorization header expected', None

    return True, None, { 'client_id': client_id, 'client_secret': client_secret, 'claims': claims, 'redirect_uri': redirect_uri }


def validate_code(code):
    claims = jwt.decode(code, secret, algorithms=['HS256'], audience=socket.gethostname())
    if claims is None:
        return False, None
    return True, claims


def _is_valid_authorize_request(request):
    if len(request.args) > 5:
        return False, "invalid_request", None

    response_type = request.args.get('response_type')
    scope = request.args.get('scope')
    client_id = request.args.get('client_id')
    state = request.args.get('state')
    redirect_uri = request.args.get('redirect_uri')

    client_info = {'client_id': client_id, 'redirect_uri': redirect_uri, 'state': state, 'scope': scope}

    if redirect_uri is None or redirect_uri == '':
        return False, 'no_redirect_uri', client_info

    if response_type is None or scope is None or client_id is None or state is None:
        return False, "invalid_request", client_info
    if response_type != 'code':
        return False, 'unsupported_response_type', client_info

    valid_scopes = ['openid', 'email']
    scopes = scope.split(' ')
    for scope in scopes:
        if scope not in valid_scopes:
            return False, "invalid_scope", client_info

    client_info = _get_client_info(client_info)

    if client_info is None:
        return False, 'unknown_client', client_info

    if redirect_uri != client_info['registered_redirect_uri']:
        return False, 'invalid_redirect_uri', client_info

    return True, '', client_info


def _get_client_info(client_info):
    try:
        client_name = redisclient.hget(client_info['client_id'], 'name')
        redirect_uri = redisclient.hget(client_info['client_id'], 'redirect_uri')
        image = redisclient.hget(client_info['client_id'], 'image')

        client_info['registered_redirect_uri'] = redirect_uri
        client_info['client_name'] = client_name

        if image is not None:
            client_info['image'] = image

        return client_info
    except Exception:
        return None
