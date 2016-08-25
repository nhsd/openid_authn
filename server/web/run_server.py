
from view import app
import logging

log = logging.getLogger('openid_connect_authenticator')
log.setLevel(logging.DEBUG)
fh = logging.FileHandler('openid_connect_authenticator.log')
fh.setLevel(logging.DEBUG)
log.addHandler(fh)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
log.info("Run server started")

app.run(debug=True, host='0.0.0.0', threaded=True)

