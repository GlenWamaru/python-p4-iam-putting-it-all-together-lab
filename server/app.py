#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash
from config import app, db, api
from models import User, Recipe
from sqlalchemy.exc import IntegrityError


# Signup resource
class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')
        
        # Create a new User instance
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            image_url=image_url,
            bio=bio
        )
        
        # Attempt to save the new user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Save the user's ID in the session object
            session['user_id'] = new_user.id
            
            # Return the user data as a JSON response with a status code of 201
            return jsonify({
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Username already exists'}), 422

# CheckSession resource
class CheckSession(Resource):
    def get(self):
        # Check if the user is logged in (user_id is in session)
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            
            # Return user data if the user is logged in
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        else:
            # Return an error message if the user is not logged in
            return jsonify({'error': 'Not logged in'}), 401

# Login resource
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Find the user by username
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Save the user's ID in the session object
            session['user_id'] = user.id
            
            # Return the user data as a JSON response
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        else:
            # Return an error message if authentication fails
            return jsonify({'error': 'Invalid credentials'}), 401

# Logout resource
class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            # Remove the user's ID from the session object
            session.pop('user_id')
            
            # Return an empty response with a status code of 204
            return '', 204
        else:
            # Return an error message if the user is not logged in
            return jsonify({'error': 'Not logged in'}), 401

# RecipeIndex resource
class RecipeIndex(Resource):
    def get(self):
        # Check if the user is logged in (user_id is in session)
        if 'user_id' in session:
            recipes = Recipe.query.all()
            recipes_data = []
            
            for recipe in recipes:
                # Convert each recipe to a dictionary
                recipe_data = {
                    'id': recipe.id,
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username
                    }
                }
                
                recipes_data.append(recipe_data)
            
            # Return a JSON response with the array of recipes
            return jsonify(recipes_data), 200
        else:
            # Return an error message if the user is not logged in
            return jsonify({'error': 'Not logged in'}), 401
    
    def post(self):
        # Check if the user is logged in (user_id is in session)
        if 'user_id' in session:
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')
            
            # Validate the inputs
            if not title:
                return jsonify({'error': 'Title is required'}), 422
            if not instructions or len(instructions) < 50:
                return jsonify({'error': 'Instructions must be at least 50 characters long'}), 422
            if not isinstance(minutes_to_complete, int):
                return jsonify({'error': 'Minutes to complete must be an integer'}), 422
            
            # Create a new Recipe instance
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )
            
            # Save the recipe to the database
            db.session.add(new_recipe)
            db.session.commit()
            
            # Return the recipe data as a JSON response with a status code of 201
            return jsonify({
                'id': new_recipe.id,
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': new_recipe.user.id,
                    'username': new_recipe.user.username
                }
            }), 201
        else:
            # Return an error message if the user is not logged in
            return jsonify({'error': 'Not logged in'}), 401

# Add resources to the API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

# Run the application
if __name__ == '__main__':
    app.run(port=5555, debug=True)
