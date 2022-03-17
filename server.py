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
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_APP_SECRET')
DATABASE_URL = os.getenv('JAWSDB_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
db = SQLAlchemy(app)
from models import Projects, Tickets

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
payload = "{\"client_id\":\"" + os.getenv('AUTH0_MANAGEMENT_API_CLIENT_ID') + "\",\"client_secret\":\"" + os.getenv(
    'AUTH0_MANAGEMENT_API_CLIENT_SECRET') + "\",\"audience\":\"https://dev--3rx-kw1.us.auth0.com/api/v2/\",\"grant_type\":\"client_credentials\"}"
headers = {'content-type': "application/json"}
conn.request("POST", "/oauth/token", payload, headers)
res = conn.getresponse()
data = res.read()
data = json.loads(data.decode("utf-8"))
MGMT_API_ACCESS_TOKEN = data['access_token']


def get_user_emails():
    """
    Returns a list of emails that are registered with Auth0
    """
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


def get_user_projects(user):
    """
    Takes an email address as an argument and returns a list of dictionaries conatining project info
    """
    user_projects_result = Projects.query.filter(Projects.projectContributors.contains(user)).all()
    projects = []
    for project in user_projects_result:
        projects.append({'title': project.projectName, 'description': project.projectDescription,
                         'contributors': project.projectContributors})
    return projects


def get_user_tickets(user):
    """
    Takes an email address as an argument and returns a list of dictionaries containing ticket info
    """
    # get the tickets that have our users email and are not already resolved
    user_tickets_result = Tickets.query.filter(Tickets.users.contains(user), Tickets.status != "Resolved").all()
    tickets_list = []
    for ticket in user_tickets_result:
        tickets_list.append({'title': ticket.name, 'description': ticket.description, 'time': ticket.estimatedTime,
                             'status': ticket.status, 'type': ticket.type, 'project': ticket.project,
                             'users': ticket.users, 'author': ticket.author, 'priority': ticket.priority})
    return tickets_list


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
    user_email = session['profile']['name']
    projects = get_user_projects(user_email)

    tickets_by_project_data = [['Project', '# of Tickets']]
    for project in projects:
        project_tickets_count = Tickets.query.filter(Tickets.project == project['title'],
                                                     Tickets.status != "Resolved").count()
        tickets_by_project_data.append([project['title'], project_tickets_count])

    tickets_by_priority_data = [['Priority', '# of Tickets'],
                                ['Immediate', Tickets.query.filter_by(priority='Immediate').count()],
                                ['High', Tickets.query.filter_by(priority='High').count()],
                                ['Medium', Tickets.query.filter_by(priority='Medium').count()],
                                ['Low', Tickets.query.filter_by(priority='Low').count()]]

    tickets_by_status_data = [['Status', '# of Tickets'],
                              ['New', Tickets.query.filter_by(status='New').count()],
                              ['In Progress', Tickets.query.filter_by(status='In Progress').count()],
                              ['Resolved', Tickets.query.filter_by(status='Resolved').count()]]

    return render_template('dashboard.html',
                           userinfo=session['profile'], userinfo_pretty=json.dumps(session['jwt_payload'], indent=4),
                           users=user_list, projects=projects, tickets_by_project_data=tickets_by_project_data,
                           tickets_by_priority_data=tickets_by_priority_data,
                           tickets_by_status_data=tickets_by_status_data)


@app.route('/tickets')
@requires_authentication
def tickets():
    user_list = get_user_emails()
    user_email = session['profile']['name']
    projects = get_user_projects(user_email)
    tickets_list = get_user_tickets(user_email)
    return render_template('tickets.html', projects=projects, users=user_list, tickets=tickets_list)


@app.route('/admin')
@requires_authentication
# @requires_authorization
def admin():
    user_list = get_user_emails()
    return render_template('admin.html', users=user_list)


@app.route('/createproject', methods=['GET'])
@requires_authentication
def create_project():
    if request.method == 'GET':
        project_name = request.args.get('projectName')
        project_description = request.args.get('projectDescription')
        project_contributors_list = request.args.getlist('selectUsers')
        # we want all users emails seperated by a space
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


@app.route('/createticket', methods=['GET'])
@requires_authentication
def create_ticket():
    if request.method == 'GET':
        ticket_name = request.args.get('ticket-title')
        ticket_description = request.args.get('ticket-description')
        ticket_time = request.args.get('ticket-time')
        ticket_type = request.args.get('ticket-type')
        ticket_status = request.args.get('ticket-status')
        ticket_priority = request.args.get('ticket-priority')
        project_select = request.args.get('project-select')
        user_select = request.args.getlist('user-select')
        ticket_author = session['profile']['name']
        ticket_datetime = datetime.now()
        # add timestamps if the ticket is already working or finished
        working_datetime = None
        completed_datetime = None
        if ticket_status == "In Progress":
            working_datetime = ticket_datetime
        elif ticket_status == "Resolved":
            completed_datetime = ticket_datetime
        # we want all users emails separated by a space
        users = ""
        for user in user_select:
            users += user + " "
        # add ticket to db
        new_ticket = Tickets(name=ticket_name, description=ticket_description, estimatedTime=ticket_time,
                             type=ticket_type, status=ticket_status, project=project_select, users=users,
                             author=ticket_author, priority=ticket_priority, created=ticket_datetime,
                             working=working_datetime, completed=completed_datetime)
        db.session.add(new_ticket)
        db.session.commit()

    # get new data for page re render
    user_list = get_user_emails()
    user_email = session['profile']['name']
    projects = get_user_projects(user_email)
    updated_tickets = get_user_tickets(user_email)

    return render_template('tickets.html', projects=projects, users=user_list, tickets=updated_tickets)


@app.route('/processticket', methods=['GET'])
@requires_authentication
def process_ticket():
    # process request
    if request.method == 'GET':
        arg = request.args.get('ticket-title')
        command = arg[:3]  # commands: res=resolved, del=delete, wor=working
        ticket_name = arg[4:]
        if ticket_name:
            ticket_row = Tickets.query.filter_by(name=ticket_name).first()
            if command == "res":  # user clicked "Checkmark" button
                ticket_row.status = "Resolved"
                ticket_row.completed = datetime.now()
                db.session.commit()
            if command == "del":  # user clicked "Trash" button
                db.session.delete(ticket_row)
                db.session.commit()
            if command == "wor":  # user clicked "Hammer" button
                ticket_row.status = "In Progress"
                ticket_row.working = datetime.now()
                db.session.commit()

    # get new data for page re render
    user_list = get_user_emails()
    user_email = session['profile']['name']
    projects = get_user_projects(user_email)
    updated_tickets = get_user_tickets(user_email)

    return render_template('tickets.html', projects=projects, users=user_list, tickets=updated_tickets)
