from flask import Flask, render_template, url_for, flash, redirect, request
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextField, TextAreaField, SelectField
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ej6swibjsk6920bj14jdzej79hfssr63fgbs'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///submissions.db'
submissions_db = SQLAlchemy(app)
db = SQLAlchemy(app)
archives_db = SQLAlchemy(app)
read_db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USER_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)
confirmed = False


user_list = []

class Course():
    def __init__(self, number, name, credits):
        self.number = number
        self.name = name
        self.credits = credits




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/", methods = ['GET', 'POST'])
def home():
    form = SubmissionForm()
    if form.validate_on_submit():
        key = secrets.token_hex(16)
        input_sub = SubmissionData(submission = form.submission.data, year = form.year.data, key = key)
        submissions_db.session.add(input_sub)
        submissions_db.session.commit()
        flash("Your submission has been entered", "success")
        return redirect(url_for("home"))
    return render_template("home.html", form = form)

def make_user():
    input_user = User(first_name = "first", last_name = "last", email = "speaks@gmail.com", username = "speaking_admin", password = "jp_speaks_admin")
    db.session.add(input_user)
    db.session.commit()

@app.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if ("speaking_admin" == str(form.username.data) and "jp_speaks_admin" == str(form.password.data)):
            user = User.query.filter_by(username = "speaking_admin").first()
            login_user(user)
            sub_list = SubmissionData.query.all()
            flash("Welcome Admin", "success")
            return redirect(url_for("submissions"))
            #return render_template("submissions.html", sub_list = sub_list)
        else:
            flash("Incorrect Credentials. Check username or password", "danger")
            return redirect(url_for("login", form = form))
    return render_template("login.html", form = form)

@app.route("/logout")
def logout():
    logout_user()
    flash("Successfully logged out", "success")
    return (redirect(url_for("home")))

@app.route("/submissions", methods = ['GET', 'POST'])
def submissions():
    if (current_user.is_authenticated):
        sub_list = SubmissionData.query.all()
        return render_template("submissions.html", sub_list = sub_list)
    else:
        flash("You do not have rights to access this page", "danger")
        return redirect(url_for("home"))

class SubmissionForm(FlaskForm):
    submission = TextAreaField("Submission", validators = [Length(min = 2, max = 1000), DataRequired()], render_kw={"rows": 5, "cols": 0})
    year = StringField("Year", validators = [DataRequired()])
    submit = SubmitField("Submit")

class ReadForm(FlaskForm):
    area = TextAreaField("Submission", render_kw={"rows": 8, "cols": 0})
    reading = SelectField("Mark as Read", choices = [("Select", "Select"), ("Yes", "Yes"), ("No", "No")])
    posting = SelectField("Post?", choices = [("Select", "Select"), ("Yes", "Yes"), ("No", "No")])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField("Username", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])
    submit = SubmitField("Submit")



class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators = [DataRequired(), Length(min = 2, max = 30)])
    last_name = StringField('Last Name', validators = [DataRequired(), Length(min = 2, max = 30)])
    username = StringField('Username', validators = [DataRequired(), Length(min = 2, max = 30)])
    email = StringField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username = username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        email_string = User.query.filter_by(email = email.data).first()
        if email_string:
            raise ValidationError('That email is taken. Please choose a different one.')

@app.route("/submissioninfo/<id>", methods = ['GET', 'POST'])
def submission_info(id):
    submission = SubmissionData.query.filter_by(key = id).first()
    year = submission.year
    read_form = ReadForm()
    form = SubForm()
    read_form.area.data = submission.submission
    if (read_form.validate_on_submit()):
        flash("Success", "success")
        if(str(read_form.reading.data) == str("Yes")):
            read = ReadData(id = submission.id, submission = submission.submission, year = submission.year, key = submission.key)
            read_db.session.add(read)
            read_db.session.commit()
            return redirect(url_for("submissions"))
    return render_template("submissioninfo.html", form = form, year = year, read_form = read_form)

@app.route("/archive/<id>", methods = ['GET', 'POST'])
def archive_post(id):
    submission = SubmissionData.query.filter_by(key = id).first()
    input_archive = ArchivesData(id = submission.id, submission = submission.submission, year = submission.year, key = submission.key)
    archives_db.session.add(input_archive)
    archives_db.session.commit()
    SubmissionData.query.filter_by(key = "{}".format(submission.key)).delete()
    submissions_db.session.commit()
    return redirect(url_for("submissions"))

@app.route("/archives", methods = ['GET', 'POST'])
def archives():
    if (current_user.is_authenticated):
        archive_list = ArchivesData.query.all()
        return render_template("archives.html", sub_list = archive_list)
    else:
        flash("You do not have rights to access this page", "danger")
        return redirect(url_for("home"))

@app.route("/archivesinfo/<id>", methods = ['GET', 'POST'])
def archives_info(id):
    submission = ArchivesData.query.filter_by(key = id).first()
    year = submission.year
    form = SubForm()
    form.area.data = submission.submission
    return render_template("archivesinfo.html", form = form, year = year)



class SubForm(FlaskForm):
    area = TextAreaField("Submission", render_kw={"rows": 8, "cols": 0})

class SubmissionData(submissions_db.Model):
    id = submissions_db.Column(submissions_db.Integer, primary_key = True)
    submission = submissions_db.Column(submissions_db.String(3000))
    year = submissions_db.Column(submissions_db.String(100))
    key = submissions_db.Column(submissions_db.String(200))

    def __repr__(self):
        return "Submission({} {} {})".format(self.submission, self.year, self.key)

class ArchivesData(archives_db.Model):
    id = archives_db.Column(archives_db.Integer, primary_key = True)
    submission = archives_db.Column(archives_db.String(3000))
    year = archives_db.Column(archives_db.String(100))
    key = archives_db.Column(archives_db.String(200))

class ReadData(read_db.Model):
    id = read_db.Column(read_db.Integer, primary_key=True)
    submission = read_db.Column(read_db.String(3000))
    year = read_db.Column(read_db.String(100))
    key = read_db.Column(read_db.String(200))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    username = db.Column(db.String(20))
    email = db.Column(db.String(120))
    password = db.Column(db.String(60))

    def __repr__(self):
        return "User({}, {}, {}, {})".format(self.first_name, self.last_name, self.username, self.email)

    '''new'''
    def get_reset_token(self, expires_sec = 3600):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)









if __name__ == '__main__':
    app.run(debug = True)

