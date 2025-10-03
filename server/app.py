#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


# ---------- AUTH ROUTES ----------


class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )
            user.password_hash = data.get("password")

            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username already taken"]}, 422
        except ValueError as e:
            return {"errors": [str(e)]}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {}, 401


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get("username")).first()

        if user and user.authenticate(data.get("password")):
            session["user_id"] = user.id
            return user.to_dict(), 200
        return {"errors": ["Invalid username or password"]}, 401


class Logout(Resource):
    def delete(self):
        session.pop("user_id", None)
        return {}, 204


# ---------- RECIPES ROUTES ----------


class RecipeIndex(Resource):
    def get(self):
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"errors": ["Unauthorized"]}, 401

        data = request.get_json()
        try:
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except ValueError as e:
            return {"errors": [str(e)]}, 422


# ---------- REGISTER RESOURCES SAFELY ----------


def register_resources():
    """Register API resources once (avoid duplicate endpoint errors during pytest)."""
    existing_endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}

    if "signup" not in existing_endpoints:
        api.add_resource(Signup, "/signup", endpoint="signup")

    if "check_session" not in existing_endpoints:
        api.add_resource(CheckSession, "/check_session", endpoint="check_session")

    if "login" not in existing_endpoints:
        api.add_resource(Login, "/login", endpoint="login")

    if "logout" not in existing_endpoints:
        api.add_resource(Logout, "/logout", endpoint="logout")

    if "recipes" not in existing_endpoints:
        api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


# Run registration once at import time
register_resources()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=5555, debug=True)
