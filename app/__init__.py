from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_migrate import Migrate
from app.helpers import liked_by_user


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'c94c8f7d61d9a8e5e31c6b0346a524za'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blogpost.db'  # SQLite for local dev
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize extensions
db = SQLAlchemy(app)
Session(app)
migrate = Migrate(app, db)

app.jinja_env.filters['liked_by_user'] = liked_by_user

# Import routes at the end to avoid circular imports
from app import routes, models 
