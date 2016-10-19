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

secret = '-----BEGIN CERTIFICATE-----MIIEiTCCA3GgAwIBAgIEUpgjODANBgkqhkiG9w0BAQUFADBTMRIwEAYKCZImiZPyLGQBGRYCdWsxEzARBgoJkiaJk/IsZAEZFgNuaHMxEzARBgNVBAMTCklBTUVOVFJVU1QxEzARBgNVBAMTCklBTUVOVFJVU1QwHhcNMTYwMjE3MTYzMjM1WhcNMTgwMjE3MTcwMjM1WjA2MQwwCgYDVQQKEwNuaHMxDzANBgNVBAsTBnBlb3BsZTEVMBMGA1UEAxMMMTUwMjQwMDEyMTA2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzrwcB7nU9wtSbXph4eDv5phyrXEOl2bd46/Ke3TrAmV7j4yRa86qfNYa8/8DudLQtEy7tThLspVxxEgD+LmeSxseLVNxcIIf0WcqnaGKzn/4aDmieppN6su7N29KNw8G/6qd8i0hrAmF7xTcz5Xcynj36zSxlBQ/CvsBtfWTj9bHys5PD5yyuoSi4CPIgpqTvrk66CGmasU/AnonYi6orAvu59POUBf00+CH9HfodgMwOX0Q/5Kf/J/wKNChTgHSdGDPOcD5hFWOP7tmfb/ma96niHrB02OPHlOb5GeW0B3Au7ti5TghDCJCHjOURyS4ferJS0pYKGY7vi0DmAtspwIDAQABo4IBgDCCAXwwCwYDVR0PBAQDAgeAMIHZBgNVHR8EgdEwgc4wa6BpoGekZTBjMRIwEAYKCZImiZPyLGQBGRYCdWsxEzARBgoJkiaJk/IsZAEZFgNuaHMxEzARBgNVBAMTCklBTUVOVFJVU1QxEzARBgNVBAMTCklBTUVOVFJVU1QxDjAMBgNVBAMTBUNSTDM4MF+gXaBbhllsZGFwOi8vSUFNRU5UUlVTVC9jbj1JQU1FTlRSVVNULGNuPUlBTUVOVFJVU1QsZGM9bmhzLGRjPXVrP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZTArBgNVHRAEJDAigA8yMDE2MDIxNzE2MzIzNVqBDzIwMTcwNzEzMDkwMjM1WjAfBgNVHSMEGDAWgBT6jVIkCK4j9gBo/J5x+to3bIukLzAdBgNVHQ4EFgQUKpQeeXMbfMc+jDJ2PsEgFySlBVUwCQYDVR0TBAIwADAZBgkqhkiG9n0HQQAEDDAKGwRWOC4xAwIEsDANBgkqhkiG9w0BAQUFAAOCAQEAmwLMAHR3Z3mm79eB1jGaBP8osaF64Mye1ayRRR96VAuT+jhnGCAFDVG3xne9vPXnpqErqdFrjPqzsuEI2XxyL7sFVL0oYZ9ri1ncHsfDi4iAlFj4YawuzKMX2JYypHCDpW/LEHxyGqh7TGH43oz2mm/ZBuqRQ0T76SnwGJzlYfYlXtG1jHtmUgufqWQax2ogL6W/ApdelfDItOYVXBtaTsRWfa/euPtSGJRlXr1iuXKgxRK+6YC4rI1Ie9KSOzv2uQpOwdbMm3Ltl6YAzJuvFtwVdovBSpy69UtTc7jDZv/Ty1Rv+VReYneCuyy836MIG8jRHoPs0bZxc9NY3rkOTw==-----END CERTIFICATE-----'


@app.route('/auth', methods=['GET'])
def intermediary():
    code = request.args.get('?code')

    claims = jwt.get_unverified_claims(code)

    user = claims['sub']

    return render_template('code.html', code=user)
