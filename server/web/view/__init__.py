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
    if not _is_valid_request(request):
        return "invalid_request", 400

    #TODO: Check client ID is known ID
    #TODO: Check url is registered url

    return "OK"

def _is_valid_request(request):
    response_type = request.args.get('response_type')
    scope = request.args.get('scope')
    client_id = request.args.get('client_id')
    state = request.args.get('state')
    redirect_uri = request.args.get('request_uri')

    if response_type is None or response_type != 'code' \
            or scope is None or scope != 'openid' \
            or client_id is None \
            or state is None \
            or redirect_uri is None:
        return False

    return True

# Stub method - to be replaced with the proper one that Matt writes
def get_token(session_id):
    from datetime import datetime
    ret = {'iss': 'https://dummy.co/stuff', 'sub': '01234567', 'aud': '', 'exp': int(datetime.now().strftime("%s")) + 600, 'iat': int(datetime.now().strftime("%s"))}

    return json.dumps(ret)