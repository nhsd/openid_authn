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

@app.route('/', methods=['GET'])
def submit_credentials():
    return render_template('auth_page.html')

@app.route('/auth', methods=['GET', 'POST'])
def intermediary():
    code = request.args.get('code')
    return render_template('code.html', code=code)




