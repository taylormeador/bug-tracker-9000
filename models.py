from server import db


class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    projectName = db.Column(db.String(80), nullable=False)
    projectDescription = db.Column(db.String(500))
    projectContributors = db.Column(db.String(500))
    projectManager = db.Column(db.String(50))


class Tickets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500))
    estimatedTime = db.Column(db.Integer)
    status = db.Column(db.String(50))
    priority = db.Column(db.String(50))
    type = db.Column(db.String(50))
    project = db.Column(db.String(100))
    users = db.Column(db.String(500))
    author = db.Column(db.String(100))
    created = db.Column(db.DateTime)
    working = db.Column(db.DateTime)
    completed = db.Column(db.DateTime)


class TicketsComments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticketID = db.Column(db.Integer)
    comment = db.Column(db.String(500))
    author = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime)
