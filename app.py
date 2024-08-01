from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    current_user,
    logout_user,
    login_required,
)
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = (
    "your_secret_key"  # Replace 'your_secret_key' with a secret key of your choice
)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://flaskuser:password@localhost/flaskapp"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


# Initialize the database
with app.app_context():
    db.create_all()


# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Your account has been created! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            next_page = request.args.get("next")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login unsuccessful. Please check your email and password.", "danger")
    return render_template("login.html")


# Home Route
@app.route("/")
@login_required
def home():
    return render_template("home.html", username=current_user.username)


# Logout Route
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
