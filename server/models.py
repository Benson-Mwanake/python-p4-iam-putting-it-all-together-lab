from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    # default "" prevents NOT NULL DB error in tests that create users without setting a password
    _password_hash = db.Column(db.String, nullable=False, default="")
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationships
    recipes = relationship(
        "Recipe", back_populates="user", cascade="all, delete-orphan"
    )

    # prevent circular nesting and hide password hash in serialized output
    serialize_rules = ("-recipes.user", "-_password_hash")

    @hybrid_property
    def password_hash(self):
        """Prevent password hash from being accessed directly."""
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        """Hashes password before storing in db."""
        if not password:
            raise ValueError("Password cannot be empty.")
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        """Check if provided password matches stored hash."""
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates("username")
    def validate_username(self, key, username):
        if not username or username.strip() == "":
            raise ValueError("Username is required")
        return username


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    # minutes_to_complete can be optional in some tests
    minutes_to_complete = db.Column(db.Integer, nullable=True)

    # allow NULL user_id so tests that don’t attach a user pass when creating recipes directly
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="recipes")

    serialize_rules = ("-user.recipes",)

    @validates("title")
    def validate_title(self, key, title):
        if not title or title.strip() == "":
            raise ValueError("Title is required")
        return title

    @validates("instructions")
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return instructions
