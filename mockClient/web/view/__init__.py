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

log = logging.getLogger('view')

@app.route('/', methods=['GET'])
def submit_credentials():
    
    return render_template('auth_page.html')

@app.route('/beginlogin', methods=['GET'])
def auto_redirect():
   print("Hit auto_redirect()") 
   return redirect("http://localhost:5000/authorize?response_type=code&scope=openid&client_id=s6BhdRKgt3&state=1234&redirect_uri=http%3A%2F%2F192.168.1.6:5001%2Fauth", code=302)

secret = 'fd2q9VmSZZW2QKz5PhLP'

@app.route('/auth', methods=['GET', 'POST'])
def intermediary():
    code = request.args.get('code')
    
    claims = jwt.decode(code, secret, algorithms=['HS256'], audience='AlistairLaptop')

    user = claims['sub']

    return render_template('code.html', code=user)
