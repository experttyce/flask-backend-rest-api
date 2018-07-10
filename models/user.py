from db import db
from datetime import datetime
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
import uuid


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    salt = db.Column(db.String(255))
    created_on = db.Column(db.DateTime)

    def __init__(self, fullname, username, password):
        self.fullname = fullname
        self.email = username
        self.salt = str(uuid.uuid4())
        self.password = password
        self.created_on = datetime.utcnow()
        self.password = generate_password_hash(password)

    def json(self):
        return {
            'id': self.id,
            'fullname': self.fullname,
            'username': self.email,
            'created_at': self.created_on.isoformat()
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter(func.lower(cls.email) == func.lower(email)).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(salt=_id).first()

    @classmethod
    def valid_user(cls, password):
        return check_password_hash(cls.password, password)

    def check_password(self, password):
        return check_password_hash(self.password, password)