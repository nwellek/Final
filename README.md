This project allows users to sign in.  Then search for a POI and return the top 5 restaurants within a mile. As well as an email.

The following databases must be created
	-nwellek364Final

python main_app.py runserver

no usually imports
	
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