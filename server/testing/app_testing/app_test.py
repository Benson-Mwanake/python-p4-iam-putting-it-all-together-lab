#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


# ------------------- Signup -------------------
class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        bio = data.get("bio")
        image_url = data.get("image_url")

        if not username or not password:
            return {"error": "Username and password required"}, 422

        try:
            new_user = User(username=username, bio=bio, image_url=image_url)
            new_user.password_hash = password  # triggers bcrypt hashing

            db.session.add(new_user)
            db.session.commit()

            session["user_id"] = new_user.id

            return new_user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {"error": "Invalid signup"}, 422


# ------------------- CheckSession -------------------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        return user.to_dict(), 200


# ------------------- Login -------------------
class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return {"error": "Invalid credentials"}, 401


# ------------------- Logout -------------------
class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        session["user_id"] = None
        return {}, 204


# ------------------- RecipeIndex -------------------
class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            return {"error": "Unauthorized"}, 401

        recipes = [r.to_dict() for r in user.recipes]
        return recipes, 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()

        try:
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )

            db.session.add(new_recipe)
            db.session.commit()

            return new_recipe.to_dict(), 201

        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {"error": str(e)}, 422


# ------------------- API Routes -------------------
api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")

if __name__ == "__main__":
    app.run(port=5555, debug=True)
