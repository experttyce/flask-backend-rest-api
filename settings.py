import os


SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///data.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
JWT_SECRET_KEY = 'thisisasecretkey'
FLASK_DEBUG = True
FLASK_SERVER_NAME = 'localhost:8888'