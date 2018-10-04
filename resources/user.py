from flask_restful import Resource, reqparse
from flask import request
import datetime
from config import log
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt,
    get_jwt_claims
)
from werkzeug.security import generate_password_hash
from models.user import UserModel
from models.group import GroupModel
from blacklist import BLACKLIST
import settings
from db import db
import sys


_user_parser = reqparse.RequestParser()
_user_parser.add_argument('fullname',
                          type=str,
                          required=False,
                          help="This field cannot be blank."
                          )
_user_parser.add_argument('username',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )
_user_parser.add_argument('password',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )


class UserRegister(Resource):
    def post(self):

        data = _user_parser.parse_args()
        if data['fullname'] is None:
            return {"message": "Missing full name, is required"}, 400

        if UserModel.find_by_email(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(**data)
        try:
            user.save_to_db()
        except Exception as e:
            log.error(str(e))
            return {"message": "A error was occurred"}, 400

        return {"message": "User created successfully."}, 201


class UserList(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        claims = get_jwt_claims()
        roles = claims.get('roles')
        if len(list(item for item in roles if item["name"] == settings.USER_ADMIN_GROUP)) == 0:
            return {"message": "you don't have enough privileges to perform this operation"}, 401
        user = UserModel.query
        return {'user': [x.json() for x in user]}, 200


class User(Resource):
    """
    This resource can be useful when testing our Flask app. We may not want to expose it to public users, but for the
    sake of demonstration in this course, it can be useful when we are manipulating data regarding the users.
    """

    @classmethod
    @jwt_required
    def get(cls, user_id: int):
        claims = get_jwt_claims()
        roles = claims.get('roles')
        if len(list(item for item in roles if item["name"] == settings.USER_ADMIN_GROUP)) == 0:
            return {"message": "you don't have enough privileges to perform this operation"}, 401

        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User Not Found'}, 404
        return user.json(), 200

    @classmethod
    @jwt_required
    def delete(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User Not Found'}, 404
        user.delete_from_db()
        return {'message': 'User deleted.'}, 200

    @classmethod
    @jwt_required
    def put(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User Not found'}, 404

        data = request.json
        # return {'data': data},200
        if data.get('fullname'):
            user.fullname = data.get('fullname')
        if data.get('username'):
            user.username = data.get('username')
        if data.get('password'):
            user.password = generate_password_hash(data.get('password'))
        claims = get_jwt_claims()
        roles = claims.get('roles')
        if data.get('groups') and len(list(item for item in roles if item["name"] == settings.USER_ADMIN_GROUP)) != 0:
            reqgroups = list(map(int, data.get('groups')))
            curgroups = list(groups.id for groups in user.ugroups)
            newappend = list(set(reqgroups) - set(curgroups))
            oldremove = list(set(curgroups) - set(reqgroups))
            if newappend:
                for gid in newappend:
                    newgrp = GroupModel.find_by_id(gid)
                    if newgrp:
                        user.ugroups.append(newgrp)
            if oldremove:
                for gid in oldremove:
                    oldgrp = GroupModel.find_by_id(gid)
                    if oldgrp:
                        user.ugroups.remove(oldgrp)

        try:
            user.save_to_db()
        except Exception as e:
            log.error(str(e))
            return {"message": "A error was occurred"}, 400
        return {'message': 'User was updated'}, 200


class UserLogin(Resource):
    def post(self):
        data = _user_parser.parse_args()

        user = UserModel.find_by_email(data['username'])

        # this is what the `authenticate()` function did in security.py
        if user and user.check_password(data['password']):
            # if user and safe_str_cmp(user.password, data['password']):
            # identity= is what the identity() function did in security.py—now stored in the JWT
            # access_token = create_access_token(identity=user.id, fresh=True)
            identity = user.json()
            access_token = create_access_token(identity=identity.get('groups'), expires_delta=datetime.timedelta(hours=23),
                                               fresh=True)
            refresh_token = create_refresh_token(identity=identity.get('groups'))
            return {
                       'access_token': access_token,
                       'refresh_token': refresh_token,
                       'user': user.json(),
                        'id': user.salt
                   }, 200

        return {"message": "Invalid Credentials!"}, 401


class UserLogout(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']  # jti is "JWT ID", a unique identifier for a JWT.
        BLACKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        """
        Get a new access token without requiring username and password—only the 'refresh token'
        provided in the /login endpoint.

        Note that refreshed access tokens have a `fresh=False`, which means that the user may have not
        given us their username and password for potentially a long time (if the token has been
        refreshed many times over).
        """
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200


def init_configuration():
    db.create_all()

    Group = GroupModel.find_by_name(settings.USER_ADMIN_GROUP)
    if Group is None:
        adm = GroupModel(settings.USER_ADMIN_GROUP, 'Group for Administrators')
        mem = GroupModel(settings.USER_MEMBER_GROUP, 'Group for All members')
        adm.save_to_db()
        mem.save_to_db()
    User = UserModel.find_by_email(settings.USER_ADMIN_EMAIL)

    if User is None:
        newUser = UserModel(settings.USER_ADMIN_FULLNAME, settings.USER_ADMIN_EMAIL, settings.USER_ADMIN_PASSWORD, True)
        newUser.save_to_db()

    User = UserModel.find_by_email(settings.USER_ADMIN_EMAIL)
    currentgrp = User.ugroups
    grpexists = [item.name for item in currentgrp if item.name == settings.USER_ADMIN_GROUP]
    if len(grpexists) == 0:
        admingrp = GroupModel.find_by_name(settings.USER_ADMIN_GROUP)
        User.ugroups.append(admingrp)
        User.save_to_db()



