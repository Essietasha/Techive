from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_migrate import Migrate
from app.helpers import liked_by_user
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SESSION_TYPE'] = os.getenv('SESSION_TYPE')

# Initialize extensions
db = SQLAlchemy(app)
Session(app)
migrate = Migrate(app, db)

app.jinja_env.filters['liked_by_user'] = liked_by_user

# Import routes at the end to avoid circular imports
from app import routes, models 
