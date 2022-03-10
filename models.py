from server import db


class ProjectsModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    projectName = db.Column(db.String(80), nullable=False)
    projectDescription = db.Column(db.String(500))
    projectContributors = db.Column(db.String(500))
    projectManager = db.Column(db.String(50))


class UsersModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
