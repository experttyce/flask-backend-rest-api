from db import db
from sqlalchemy import func


class GroupModel(db.Model):
    __tablename__ = "groups"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    description = db.Column(db.String(150))

    def __init__(self, name, description):
        self.name = name
        self.description = description

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter(id=_id).first()

    @classmethod
    def find_by_name(cls, _name):
        return cls.query.filter(func.lower(cls.name) == func.lower(_name)).first()

    def json(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()