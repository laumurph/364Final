__author__ = "Lauren Murphy (laumurph)"
#Final Application for SI 364, Fall 2017

# Import statements
import os
import json
import requests
import base64
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, RadioField, BooleanField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand

from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug import secure_filename


# Configures base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'wafafoaij438afl2ljfb19nlafjf491jalakjj1g1vm4iiu098afvf4b'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/pokemon_app"
WTF_CSRF_ENABLED = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
	return dict(app=app, db=db, Pokemon=Pokemon, Image=Image, Trainer=Trainer, Region=Region, Town=Town)

# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))

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
	name = db.Column(db.String(36), unique=True)

class Image(db.Model):
	__tablename__ = 'images'
	id = db.Column(db.Integer, primary_key=True)
	image = db.Column(db.LargeBinary)
	location = db.Column(db.String(255))

class Trainer(UserMixin, db.Model):
	__tablename__ = "trainers"
	id = db.Column(db.Integer, primary_key = True)
	email = db.Column(db.String(64), unique=True)
	username = db.Column(db.String(60), unique=True)
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
def load_trainer(trainer_id):
	return Trainer.query.get(int(trainer_id)) # returns User object or None

# forms

class NewTrainerForm(FlaskForm):
	username = StringField('Username: ',validators=[Required(),Length(1,60),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
	email = StringField('Email: ',validators=[Required(), Email()])
	password = PasswordField('Password: ',validators=[Required(),EqualTo('passwordagain',message="Passwords must match")])
	passwordagain = PasswordField("Confirm Password: ",validators=[Required()])
	region = RadioField("Pick your region: ", choices=[("kanto", "Kanto"),("johto", "Johto"),("hoenn", "Hoenn"), ("sinnoh", "Sinnoh"), ('unova', "Unova"), ('kalos', "Kalos"), ('alola', "Alola")], validators=[Required()])
	photo = FileField()
	submit = SubmitField('Register Trainer')

	def validate_username(self,field):
		if Trainer.query.filter_by(username=field.data).first():
			raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

class SearchForm(FlaskForm):
	region_search = StringField("Search for a specific region: ")
	town_search = StringField("Search for a specific town: ")
	pokemon_search = StringField("Search for a specific pokemon: ")
	submit = SubmitField("Search")

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# functions to get data from the API
def get_API_data(route, name):
	try:
		data = json.loads(requests.get("https://pokeapi.co/api/v2/{}/{}".format(route, name)).text)
		return data
	except:
		return "Cannot retrieve data for that route."

# def get_pokemon_location(location):
# 	try:
# 		data = json.loads(requests.get("https://pokeapi.co/api/v2/location-area/{}".format(location)).text)
# 		try:
# 			exists = data['pokemon_encounters'][0]['pokemon']
# 		except:
# 			return "No more data"
# 		return data
# 	except:
# 		return "Unable to make the request"


#get_or_create functions and update functions

# creates image
def get_or_create_image(db_session, image_file, image_loc):
	print("running image")
	pic = db.session.query(Image).filter_by(location="static/"+image_loc).first()
	if pic:
		return pic
	else:
		pic = Image(image=image_file.read(), location="static/"+image_loc)
		db_session.add(pic)
		db_session.commit()
		return pic

# creates pokemon
def get_or_create_pokemon(db_session,pokemon_name):
	print("running pokemon")
	formatted_name=pokemon_name.lower().strip()
	pokemon = db.session.query(Pokemon).filter_by(name=formatted_name).first()
	if pokemon:
		return pokemon
	else:
		resp = get_API_data("pokemon",formatted_name)
		if type(resp) == type(''):
			return resp
		ptype= ",".join([t['type']['name'] for t in resp['types']])
		pokemon = Pokemon(ptype=ptype, name=formatted_name)
		db_session.add(pokemon)
		db_session.commit()
		return pokemon

# creates town
def get_or_create_town(db_session, town_name):
	print("running town")
	town = db.session.query(Town).filter_by(name=town_name).first()
	if town:
		return town
	else:
		town = Town(name=town_name)
		resp = get_API_data("location", town_name)
		if type(resp) == type(''):
			return resp
		elif 'detail' in resp or resp['areas'] == []:
			db_session.add(town)
			db_session.commit()
			return town
		else:
			encounters = json.loads(requests.get(resp['areas'][0]['url']).text)
			for t in encounters['pokemon_encounters']:
				poke_found = get_or_create_pokemon(db_session,t['pokemon']['name'])
				town.pokemon.append(poke_found)
			db_session.add(town)
			db_session.commit()
			return town

# creates region
def get_or_create_region(db_session,region_name):
	print("running region")
	region = db.session.query(Region).filter_by(name=region_name).first()
	if region:
		return region
	else:
		region = Region(name=region_name)
		resp = get_API_data("region", region_name.lower().strip())
		if type(resp) == type(''):
			return resp
		for location in resp['locations'][:2]:
			town = get_or_create_town(db_session, location['name'])
			print(town)
			print(town.name)
			region.towns.append(town)
		db_session.add(region)
		db_session.commit()
		return region

# creates trainer
def get_or_create_trainer(db_session, email_provided, username_provided, password_provided,region_name, photo_data = "", photo_name = "", team = []):
	print("running trainer")
	trainer = db.session.query(Trainer).filter_by(email=email_provided).first()
	if trainer:
		return trainer
	else:
		if photo_data != "":
			photo_obj = get_or_create_image(db_session, photo_data, photo_name)
			region_obj = get_or_create_region(db_session, region_name)
			if type(region_obj) == type(''):
				return region_obj
		# uses password, not password_hash, because the word password is the parameter for the functions used to generate the hash.
			trainer = Trainer(email=email_provided, username=username_provided, password = password_provided, regionid=region_obj.id, pictureid=photo_obj.id)
		else:
			region_obj = get_or_create_region(db_session, region_name)
			if type(region_obj) == type(''):
				return region_obj
			trainer = Trainer(email=email_provided, username=username_provided, password = password_provided, regionid=region_obj.id)
		for p in team:
			pokemon = get_or_create_pokemon(db_session, p)
			trainer.pokemonteam.append(pokemon)
		db_session.add(trainer)
		db_session.commit()
		return trainer
	
#updates the list of towns in a region
def update_region_towns(db_session, town):
	r_name = get_API_data('location', town.name)['region']['name']
	region = get_or_create_region(db_session, r_name)
	if town.name in [Town.query.filter_by(id=t.id).first().name for t in region.towns]:
		return "Aleady in there."
	else:
		region.towns.append(town)
		db_session.add(region)
		db_session.commit()
		return "Town has been added to your region"

#updates the list of pokemon associated with the trainer
#used on page with specific pokemon to add to a user's team
def update_team(db_session, trainer, pokemon_name):
	if pokemon_name in [Pokemon.query.filter_by(id=p_id.id).first().name for p_id in trainer.pokemonteam]:
		return "{} is already in your team, sorry!".format(pokemon_name.capitalize())
	else:
		pokemon = get_or_create_pokemon(db_session, pokemon_name)
		trainer.pokemonteam.append(pokemon)
		db_session.add(trainer)
		db_session.commit()
		return "{} has been added to your team, congrats!".format(pokemon_name.capitalize())

# views and respective routes.

#main page
@app.route('/')
def index():
	return render_template('index.html')


# log in page
@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Trainer.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			session['logged_in'] = True
			return redirect(request.args.get('next') or url_for('personal_page'))
		flash('Invalid username or password.')
	return render_template('login.html',form=form)

# log out page
@app.route('/logout')
@login_required
def logout():
	session['logged_in']=False
	logout_user()
	return redirect(url_for('index'))

# registration page
@app.route('/register',methods=["GET","POST"])
def register():
	form = NewTrainerForm()
	if form.validate_on_submit():
		get_or_create_trainer(db.session, form.email.data, form.username.data, form.password.data,form.region.data, form.photo.data, secure_filename(form.photo.data.filename))
		if form.photo.data:
			form.photo.data.save('static/' + secure_filename(form.photo.data.filename))
		session['logged_in'] = True
		return redirect(url_for('login'))
	if Trainer.query.filter_by(email=form.email.data).first():
			flash('You have already made an account with this email. Please log in instead.')
			return render_template('register.html',form=form)
	return render_template('register.html',form=form)

# user's home page - must be logged in to see
@app.route('/personal', methods=['GET', 'POST'])
@login_required
def personal_page():
	try:
		image_data = Image.query.filter_by(id=current_user.pictureid).first()
		image_binary = base64.b64encode(image_data.image).decode('ascii')
	except:
	 	image_binary = ""
	region_name = Region.query.filter_by(id=current_user.regionid).first().name
	team_names = [Pokemon.query.filter_by(id=p_id.id).first().name for p_id in current_user.pokemonteam]
	if team_names == []:
		team_names = None
	resp = (current_user.username, image_binary, region_name.capitalize(), team_names)
	return render_template('personal_page.html', resp=resp, data=list)

# search page
@app.route('/search', methods=["GET","POST"])
def search():
	form = SearchForm()
	if form.validate_on_submit():
		if form.region_search.data or form.town_search.data or form.pokemon_search.data:
			try:
				kind = ""
				if form.region_search.data:
					resp = get_or_create_region(db.session, form.region_search.data.lower().strip())
					kind="Region"
					t_len = len(resp.towns.all())
					example_town = resp.towns[0].name.replace('-', ' ').title()
					return render_template('single_response.html', resp = (kind, resp, t_len), name = resp.name.capitalize(), example = example_town)
				elif form.town_search.data:
					resp = get_or_create_town(db.session, form.town_search.data.lower().strip().replace(" ", "-"))
					kind="Location"
					update_response = update_region_towns(db.session, resp)
					regionids = Region.query.join(maps).join(Town).filter(maps.c.town_id == resp.id).all()
					names = [Region.query.filter_by(id=r_id.id).first().name.capitalize() for r_id in regionids]
					n_len = len(names)
					poke = [Pokemon.query.filter_by(id=p.id).first().name.replace("-", " ").title() for p in resp.pokemon]
					return render_template('single_response.html', resp = (kind, resp, (names, n_len), poke), name = resp.name.replace('-', ' ').title())
				else:
					resp = get_or_create_pokemon(db.session, form.pokemon_search.data.lower().strip().replace(" ", "-").replace(".", ""))
					kind="Pokemon"
					type = resp.ptype
					if ',' in type:
						type = type.split(',')
						type = " and ".join(type)
					else:
						type= type
					return render_template('single_response.html', resp = (kind, resp, type), name = resp.name.replace("-", " ").title() )
			except:
				flash("Sorry, it looks like your search was misspelt or data was unable to be returned. Try again with something different!")
				return render_template('search.html', form=form)
		else:
			flash("Sorry, you must search for something.")
	return render_template('search.html', form=form)

@app.route("/added-team-member", methods = ["POST", "GET"])
@login_required
def add_pokemon():
	if request.method == "GET":
		arg = request.args.get('answer')
		resp = update_team(db.session,current_user,arg)
		return render_template('team_result.html', response= resp)
	else:
		return "Still trying sorry"
	

if __name__ == '__main__':
	db.create_all()
	manager.run()
