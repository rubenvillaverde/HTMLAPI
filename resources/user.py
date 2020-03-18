from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp 

from flask_jwt_extended import (
    create_access_token,
    set_access_cookies,
    set_refresh_cookies,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt 
)
from models.user import UserModel
from blacklist import BLACKLIST
from flask import json, jsonify, render_template, request, session, make_response



_user_parser = reqparse.RequestParser()
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

        if UserModel.find_by_username(data['username']):
            #return {"message": "A user with that username already exists"}, 400
            mensaje="Usuario ya existe con este nombre"
            return make_response(render_template('register3.html', mensaje=mensaje))

        user = UserModel(**data)
     
        user.save_to_db()

        #return {"message": "User created successfully."}, 201
        return make_response(render_template('home.html'))


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user=UserModel.find_by_id(user_id)
        if user is None:
            return {'message':'user not found'}, 404
        return user.json()
        

    @classmethod
    def delete(cls,user_id):
        user = UserModel.find_by_id(user_id)
        if user is None:
            return{'message':'user not found'}, 404
        user.delete_from_db()
        return {'message':'User deleted'}, 200
        

class UserLogin(Resource):
    

    @classmethod
    def post(cls):
        
        data=_user_parser.parse_args()
        username=request.form['username']
        password=request.form['password']
        #user=UserModel.find_by_username(data['username'])
        user=UserModel.find_by_username(username)
        
        if user is not None and user.password==password:
                       
            access_token=create_access_token(identity=user.id, fresh=True)
            refresh_token=create_refresh_token(user.id)
            session['access_token']=access_token
            
            #return{'access_token':access_token, 'refresh_token':refresh_token}, 200
            return make_response(render_template('home.html'))
            
            
        return {'message':'Invalid credentials'}, 401

class UserLogout(Resource):
    @jwt_required
    def post(self):
                
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        mensaje={'message':'succesfully log out'}
        #return {'message':'succesfully log out'}, 200
        return make_response(render_template("logout3.html", message=mensaje['message']))







class TokenRefresh(Resource):
    
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token=create_access_token(identity=current_user, fresh=False)
        
        return {'acces_token':new_token}, 200

