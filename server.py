# /server.py

from functools import wraps
import json
import os
from werkzeug.exceptions import HTTPException
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
import redis
from requests import request

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_APP_SECRET')
DATABASE_URL = os.getenv('JAWSDB_URL')

# Configure Redis for storing the session data on the server-side
redis_url = os.getenv('REDISTOGO_URL')
redis = redis.from_url(redis_url)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis

#OAuth
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id='jPZYhRfytp9AO0gav3OdHpY4mPxHQPUG',
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    api_base_url='https://dev--3rx-kw1.us.auth0.com',
    access_token_url='https://dev--3rx-kw1.us.auth0.com/oauth/token',
    authorize_url='https://dev--3rx-kw1.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('https://dev--3rx-kw1.us.auth0.com/userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='https://bug-tracker-9000.herokuapp.com/callback')


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('login', _external=True), 'client_id': 'jPZYhRfytp9AO0gav3OdHpY4mPxHQPUG'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/')
@app.route('/dashboard')
@requires_authentication
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))


@app.route('/tickets')
def tickets():
    return render_template('tickets.html')


@app.route('/admin')
# @requires_authorization
def admin():
    user_list = ["Dev 1", "Dev 2", "Project Manager 1"]
    return render_template('admin.html', users=user_list)


@app.route('/createproject', methods=['POST'])
def createproject():
    project_name = request.form.get('projectName')
    project_description = request.form.get('projectDescription')
    project_personnel = request.form.get('projectPersonnel')
    return project_name, project_description, project_personnel
