#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        data = request.get_json()
        print(data.get('username'))
        try:
            new_user = User(
                username=data.get('username'),
                image_url = data.get('image_url'),
                bio = data.get('bio')
            )

            new_user.password_hash = data['password']

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return new_user.to_dict(), 201
        
        except IntegrityError as e:
            return {'errors': [str(e)]}, 422

class CheckSession(Resource):
    
    def get(self):
        if session['user_id']:
            user = User.query.filter_by(id=session.get('user_id')).first()
            return user.to_dict(), 200
        return {'error': 'not logged in'}, 401

class Login(Resource):
    
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']
        
        user = User.query.filter_by(username=username).first()
            
        if user:
            if user.authenticate(password=password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        
        return {'error': 'password or username is incorrect'}, 401

class Logout(Resource):
    
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        
        return {'error': 'not logged in'}, 401

class RecipeIndex(Resource):

    def get(self):
        if session['user_id']:
            recipes = Recipe.query.all()
            return [recipe.to_dict() for recipe in recipes], 200
        
        return {'error': 'Please sign in'}, 401
    
    def post(self):
        if session['user_id']:
            data = request.get_json()

            try:
                recipe = Recipe(
                    title=data.get('title'),
                    user_id=session.get('user_id'),
                    instructions=data.get('instructions'),
                    minutes_to_complete=data.get('minutes')
                )

                db.session.add(recipe)
                db.session.commit()

                return recipe.to_dict(), 201
            
            except ValueError as e:
                return [str(e)], 422
        
        return {'error': 'Please log in'}

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
