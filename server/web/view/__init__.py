from flask import Flask, request, render_template, session, redirect, current_app, g
from urllib.request import urlopen
from urllib.parse import urlencode
import random
import json
import os, requests
from functools import wraps
import logging
from storage import redisclient

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
    (valid, reason, context) = _is_valid_authorize_request(request)
    if not valid:
        if reason == 'no_redirect_uri':
            return render_template('error.html', \
                message="The client you have come from is not properly configured. Please go back.")

        uri = context['redirect_uri'] + '?'
        if context['state'] is not None:
            uri += 'state=' + context['state'] + '&'

        if reason == 'unknown_client' or reason == 'invalid_redirect_uri':
            return render_template('error.html', \
                message="You've come from a client we don't recognise so we can't sign you in.", \
                redirect=[uri+'error=access_denied'])

        uri += 'error=' + reason
        return redirect(uri, code=302)
    return render_template('login.html', errorMessage = "", client_id = context['client_id'], redirect_uri = context['redirect_uri'], state = context['state'])

@app.route('/credentialsSubmitted', methods=['GET', 'POST'])
def submit_credentials():
    stored_username = redisclient.hget('user:1000', 'username')
    stored_password = redisclient.hget('user:1000', 'password')

    entered_username = request.form['user']
    entered_password = request.form['passw']
    redirect_uri = request.form['redirect_uri']
    state = request.form['state']
    client_id = request.form['client_id']

    if stored_username == entered_username and stored_password == entered_password:
        return render_template('auth_page.html', client_id = client_id, redirect_uri = redirect_uri, state = state)
    else:
        return render_template('login.html', errorMessage = "Incorrect username or password.", client_id = client_id, redirect_uri = redirect_uri, state = state)

@app.route('/authorisationSubmitted', methods=['GET', 'POST'])
def auth_submit():
    authResponse = request.form['auth']

    uri = request.form["redirect_uri"]

    if authResponse == "Cancel":
        return redirect(uri + '?error=access_denied&state=' + request.form["state"], code=302)
    token = generateToken()

    return redirect(uri + "code=" + token + "&state=" + request.form['state'])

def generateToken():
    return "Greetings"



def _is_valid_authorize_request(request):

    if len(request.args) > 5:
        return False, "invalid_request", None

    response_type = request.args.get('response_type')
    scope = request.args.get('scope')
    client_id = request.args.get('client_id')
    state = request.args.get('state')
    redirect_uri = request.args.get('redirect_uri')

    context = { 'client_id': client_id, 'redirect_uri': redirect_uri, 'state': state }

    if redirect_uri is None or redirect_uri == '':
        return False, 'no_redirect_uri', context

    if response_type is None or scope is None or client_id is None or state is None:
        return False, "invalid_request", context
    if response_type != 'code':
        return False, 'unsupported_response_type', context

    if scope != 'openid':
        return False, "invalid_scope", context

    #TODO: Get client info from redis
    client_info = _get_client_info(client_id)

    if client_info is None:
        return False, 'unknown_client', context

    if redirect_uri != client_info['redirect_uri']:
        return False, 'invalid_redirect_uri', context

    return True, '', context

def _get_client_info(client_id):
    if client_id == "example":
        return { 'client_id': 'example', 'redirect_uri': 'https://client.example.org/cb' }
    return None

# Stub method - to be replaced with the proper one that Matt writes
def get_token(session_id):
    from datetime import datetime
    ret = {'iss': 'https://dummy.co/stuff', 'sub': '01234567', 'aud': '', 'exp': int(datetime.now().strftime("%s")) + 600, 'iat': int(datetime.now().strftime("%s"))}

    return json.dumps(ret)