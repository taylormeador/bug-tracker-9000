# /server.py

from functools import wraps
import json
import os
from werkzeug.exceptions import HTTPException
from flask import Flask, jsonify, redirect, render_template, session, url_for, request
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
import redis
import http.client

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_APP_SECRET')
DATABASE_URL = os.getenv('JAWSDB_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
db = SQLAlchemy(app)
from models import Projects, Users

# Configure Redis for storing the session data on the server-side
redis_url = os.getenv('REDISTOGO_URL')
redis = redis.from_url(redis_url)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis

# OAuth
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

# request auth0 management access token
conn = http.client.HTTPSConnection("dev--3rx-kw1.us.auth0.com")
payload = "{\"client_id\":\"" + os.getenv('AUTH0_MANAGEMENT_API_CLIENT_ID') + "\",\"client_secret\":\"" + os.getenv('AUTH0_MANAGEMENT_API_CLIENT_SECRET') + "\",\"audience\":\"https://dev--3rx-kw1.us.auth0.com/api/v2/\",\"grant_type\":\"client_credentials\"}"
headers = { 'content-type': "application/json" }
conn.request("POST", "/oauth/token", payload, headers)
res = conn.getresponse()
data = res.read()
data = json.loads(data.decode("utf-8"))
MGMT_API_ACCESS_TOKEN = data['access_token']


def get_user_emails():
    # get json of users from auth0 management api
    conn = http.client.HTTPSConnection("dev--3rx-kw1.us.auth0.com")
    headers = {'authorization': "Bearer " + MGMT_API_ACCESS_TOKEN}
    conn.request("GET", "https://dev--3rx-kw1.us.auth0.com/api/v2/users", headers=headers)
    res = conn.getresponse()
    data = res.read()
    json_data = json.loads(data.decode("utf-8"))
    # return list of emails
    user_list = []
    for user in json_data:
        user_list.append(user['email'])
    return user_list


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
    user_list = get_user_emails()
    projects = [{"title": "bug tracker", "description": "test description", "contributors": "Taylor@gmail.com"},
                {"title": "other project", "description": "test description", "contributors": "Taylor@gmail.com"},
                {"title": "test tracker", "description": "test", "contributors": "Taylor@gmail.com"}]
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4), users=user_list, projects=projects)


@app.route('/tickets')
def tickets():
    return render_template('tickets.html')


@app.route('/admin')
# @requires_authorization
def admin():
    user_list = get_user_emails()
    return render_template('admin.html', users=user_list)


@app.route('/createproject', methods=['GET'])
def createproject():
    if request.method == 'GET':
        project_name = request.args.get('projectName')
        project_description = request.args.get('projectDescription')
        project_contributors_list = request.args.getlist('selectUsers')
        project_contributors = ""
        for contributor in project_contributors_list:
            project_contributors += contributor + " "
        project_manager = session['profile']['name']
        # add the new project to the db
        new_project = Projects(projectName=project_name, projectDescription=project_description,
                               projectContributors=project_contributors, projectManager=project_manager)
        db.session.add(new_project)
        db.session.commit()
        return render_template('dashboard.html')

