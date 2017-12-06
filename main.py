__author__ = "Lauren Murphy (laumurph)"
#Final Application for SI 364, Fall 2017

# Import statements
import os
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Configures base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'wafafoaij438afl2ljfb19nlafjf491jalakjj1g1vm4iiu098afvf4b'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/pokemon_app"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Set up email config stuff
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SUBJECT_PREFIX'] = '[Songs App]'
app.config['MAIL_SENDER'] = 'Admin <>'
app.config['ADMIN'] = os.environ.get('ADMIN')

# App addition setups
manager = Manager(app)
db = SQLAlchemy(app) # For database use
migrate = Migrate(app, db) # For database use/updating
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

## Set up Shell context
def make_shell_context():
    return dict(app=app, db=db, ) #TODO: fix up the make_shell_context so that I add in the tables like User=User

# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))





##### Functions to send email #####
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, template, **kwargs): # kwargs = 'keyword arguments', this syntax means to unpack any keyword arguments into the function in the invocation...
    msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg]) # using the async email to make sure the email sending doesn't take up all the "app energy" -- the main thread -- at once
    thr.start()
    return thr # The thread being returned
    
#Models
#association table between regions and towns
maps = db.Table('maps', db.Column('town_id', db.Integer, db.ForeignKey("towns.id")), db.Column('region_id', db.Integer, db.ForeignKey('regions.id')))

#association table between pokemon and towns
spottings = db.Table('spottings', db.Column('town_id', db.Integer, db.ForeignKey("towns.id")), db.Column('pokemon_id', db.Integer, db.ForeignKey('pokemon.id')))

#association table between trainers and pokemon
teams = db.Table('teams', db.Column('pokemon_id', db.Integer, db.ForeignKey('pokemon.id')), db.Column('trainer_id', db.Integer, db.ForeignKey('trainers.id')))

class Pokemon(db.Model):
	__tablename__ = 'pokemon'
	id = db.Column(db.Integer, primary_key = True)
	ptype = db.Column(db.String(36))
	typeid = db.Column(db.Integer
	#trainer_id = db.Column(db.Integer, db.ForeignKey('trainers.id'))
	## fields for stats TODO

## may be buggy, depends on if it was correctly implemented. Watch out.
class Image(db.Model):
	__tablename__ = 'images'
	id = db.Column(db.Integer, primary_key=True)
	image = db.Column(db.LargeBinary)
	location = db.Column(db.String(255))

class User(UserMixin, db.Model):
    __tablename__ = "trainers"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    pokemonteam = db.relationship("Pokemon", secondary=teams, backref=db.backref('trainers',lazy='dynamic'), lazy='dynamic')
    regionid = db.Column(db.Integer, db.ForeignKey('regions.id'))
    pictureid = db.Column(db.Integer, db.ForeignKey('images.id'))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Region(db.Model):
	__tablename__ = "regions"
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(64), unique = True)
	towns = db.relationship('Town',secondary=maps,backref=db.backref('regions',lazy='dynamic'),lazy='dynamic')

class Town(db.Model):
	__tablename__ = "towns"
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(64), unique = True)
	pokemon = db.relationship("Pokemon", secondary=spottings, backref=db.backref('towns', lazy='dynamic'), lazy='dynamic')




## DB load function
## Necessary for behind the scenes login manager that comes with flask_login capabilities! Won't run without this.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # returns User object or None

# TODO: Add forms here

# TODO: Error handlers

# TODO: get_or_create functions that come here.

# TODO: add in views and respective routes.



if __name__ == '__main__':
    db.create_all()
    manager.run()
