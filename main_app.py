import requests
import json
import csv
import os
import plotly.plotly as py
import pandas as pd
from flask import Flask, request, render_template, make_response, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, Form
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_script import Manager, Shell
from wtforms.validators import Required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_mail import Mail, Message
from threading import Thread
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from flask import jsonify


app = Flask(__name__)
app.debug = True 

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/nwellek364Final"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587 #default
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nwellek364@gmail.com'
app.config['MAIL_PASSWORD'] = "bariisinthisclass"
app.config['MAIL_SUBJECT_PREFIX'] = '[Resturant Results]'
app.config['MAIL_SENDER'] = 'nwellek364@gmail.com' 
app.config['ADMIN'] = 'nwellek364@gmail.com' 

app.config['SECRET_KEY'] = 'hardtoguessstring'

# Set up Flask debug stuff
manager = Manager(app)
db = SQLAlchemy(app) # For database use
migrate = Migrate(app, db) # For database use/updating
manager.add_command('db', MigrateCommand) # Add migrate
mail = Mail(app)
google_key = "AIzaSyCRQKx-rs1IRg-mlG11KrY412tnyUvs8w8"

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)

def send_email(to, subject, template, **kwargs): 
	msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
				  sender=app.config['MAIL_SENDER'], recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg]) 
	thr.start()
	return thr

def get_cords(search):
	geocode_url = "https://maps.googleapis.com/maps/api/geocode/json?address={}&sensor=false&key={}".format(search, google_key)
	page = requests.get(geocode_url).json()
	latitude = page["results"][0]["geometry"]["location"]["lat"]
	longitude = page["results"][0]["geometry"]["location"]["lng"]
	lat_long = (latitude, longitude)
	return lat_long 
#print (get_cords("Michigan Stadium"))

def get_rest(lat_long, poi_name, current_user):
	off_url = "https://api.yelp.com/oauth2/token"
	client_id = "nm9ukheorKDoZu0iStVXOg"
	client_secret = "OdlsYyyRAYgpAWyRyjPM1PYcKNRCdihW5NZDjKGrzaeAVOBwMmHr07as9GUjeNkw"
	response = requests.post(off_url, data = {"grant_type":"client_credentials", "client_id":client_id, "client_secret":client_secret}).json()
	access_token = response["access_token"]
	lat,lng = lat_long
	yelp_url = "https://api.yelp.com/v3/businesses/search?latitude={}&longitude={}&term=restaurants&radius=4800&sort_by=rating".format(lat, lng)
	response2 = requests.get(yelp_url, headers = {"Authorization" : "Bearer {}".format(access_token)}).json()
	particular_poi = get_or_create_POI(db.session, poi_name)
	new_search = Search(user_id=current_user.id, POI_id=particular_poi.POI_id)
	db.session.add(new_search)
	db.session.commit()
	for res in response2["businesses"]:
		get_or_create_restuarant(db.session, res["name"], particular_poi.POI_id, " ".join(res["location"]['display_address']), res['rating'])
	return ([	biz["name"] for biz in response2["businesses"][:5]])
#print (get_rest(get_cords("Michigan Stadium")))    

class User(UserMixin, db.Model):
	__tablename__ = "user"
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64), unique=True)
	password_hash = db.Column(db.String(200), unique=True)    
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

## DB load functions
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id)) # returns User object or None

class RegistrationForm(FlaskForm):
	email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	submit = SubmitField('Register User')

	#Additional checking methods for the form
	def validate_email(self,field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')


class POI(db.Model):
	__tablename__ = "POI"
	POI_id = db.Column(db.Integer, primary_key=True)
	POI_Name = db.Column(db.String(64), unique=True)
	lat = db.Column(db.Float(10), unique=True)  
	lng = db.Column(db.Float(10), unique=True)
	def __repr__(self):
		return "{}, {}, {}".format(self.POI_Name,self.lat,self.lng)

class Search(db.Model):
	__tablename__ = "search"
	search_id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	POI_id = db.Column(db.Integer, db.ForeignKey('POI.POI_id'))

class Restuarant(db.Model):
	__tablename__ = "Restaurant"
	POI_id = db.Column(db.Integer)
	restaurant_id = db.Column(db.Integer, primary_key=True)
	restaurant_name = db.Column(db.String(64))
	restaurant_add = db.Column(db.String(200))
	restaurant_rating = db.Column(db.Float)


def get_or_create_POI(db_session, POI_Name):
	specificPOI = db_session.query(POI).filter_by(POI_Name=POI_Name).first()
	if specificPOI:
		return specificPOI
	else:
		lat, lng = get_cords(POI_Name)
		specificPOI = POI(POI_Name=POI_Name, lat=lat, lng=lng)
		db_session.add(specificPOI)
		db_session.commit()
		return specificPOI
#print(get_or_create_POI(db.session, "Michigan Stadium"))

def get_or_create_restuarant(db_session, res_name, poi_id, address, rating):
	restaurant = db_session.query(Restuarant).filter_by(restaurant_name=res_name, POI_id=poi_id).first()
	if restaurant:
		return restaurant
	else:
		new_POI = db_session.query(POI).filter_by(POI_id=poi_id).first()
		new_res = Restuarant(POI_id=new_POI.POI_id, restaurant_name=res_name, restaurant_add=address, restaurant_rating=rating) 
		db_session.add(new_res)
		db_session.commit()
		return new_res        


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class POIForm(FlaskForm):
	POI = StringField('Enter a location Point Of Interest: (Michigan Stadium)')
	submit = SubmitField('Submit')

## Login routes
@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('index'))
		flash('Invalid username or password.')
	return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,password=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in!')
		return redirect(url_for('login'))
	return render_template('register.html',form=form)
	
@app.route('/')
@login_required
def index():
	form = POIForm()
	return render_template("POI.html", form=form)
	#return render_template('POI.html', form = form)

@app.route('/top_5',methods=["POST"])
@login_required
def top_5():
	form = POIForm()
	search_poi = form.POI.data
	coords = get_cords(search_poi)
	rest_list = get_rest((coords[0], coords[1]), search_poi, current_user)
	send_email(current_user.email, "Top 5 Restaraunts Near {}".format(search_poi), "mail/top5", search_poi=search_poi, lst=rest_list)
	return render_template("top5.html",search_poi=search_poi, lst=rest_list)


@app.route('/rest_detail/<name>')
@login_required
def rest_detail(name):
	restaurant = db.session.query(Restuarant).filter_by(restaurant_name=name).first()
	return render_template("rest_detail.html", rest = restaurant)

@app.route("/json")
@login_required
def json():
	return jsonify({
		"history": [x.POI.POI_Name for x in db.session.query(Search,POI).filter(Search.user_id == current_user.id).join(POI).all()]
	})

@app.route('/map')
def image():
	return render_template('image.html')    

@app.errorhandler(404)
def fouronefour(e):
	return render_template("404.html")

@app.errorhandler(405)
def fouronefive(e):
	return render_template("405.html")              

if __name__ == '__main__':
	db.create_all()
	manager.run()   
