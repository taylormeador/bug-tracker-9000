from flask import Flask, render_template

# Flask, db setup
app = Flask(__name__)
app.secret_key = "secret"


@app.route("/")
def index():
    return render_template("index.html")
