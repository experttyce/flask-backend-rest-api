from db import db
from datetime import datetime
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from models.group import GroupModel
import settings

users_groups = db.Table('users_groups',
                        db.Column('id', db.Integer, primary_key=True),
                        db.Column('user_id', db.Integer,
                                  db.ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')
                                  ),
                        db.Column('group_id', db.Integer,
                                  db.ForeignKey('groups.id', onupdate='CASCADE', ondelete='CASCADE'))
                        )


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    salt = db.Column(db.String(255))
    created_at = db.Column(db.DateTime)
    ugroups = db.relationship('GroupModel', secondary=users_groups,
                              backref=db.backref('groups', lazy='dynamic'))

    def __init__(self, fullname, username, password, confirmed=False):
        self.fullname = fullname
        self.email = username
        self.salt = str(uuid.uuid4())
        self.password = password
        self.created_at = datetime.utcnow()
        self.password = generate_password_hash(password)
        self.confirmed = confirmed
        grp = GroupModel.find_by_name(settings.USER_MEMBER_GROUP)
        if grp:
            self.ugroups.append(grp)

    def json(self):
        return {
            'id': self.id,
            'fullname': self.fullname,
            'username': self.email,
            'created_at': self.created_at.isoformat(),
            'groups': [groups.json() for groups in self.ugroups]
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