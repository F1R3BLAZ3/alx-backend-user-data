#!/usr/bin/env python3
"""
Auth module
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def _generate_uuid() -> str:
    """
    Generate a new UUID string.

    Returns:
        str: A string representation of the new UUID.
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user with an email and password.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            User: The created User object.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Check if the login credentials are valid.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            bool: True if the login credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session for the user with the given email.

        Args:
            email (str): The user's email.

        Returns:
            str: The session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            user.session_id = session_id
            self._db._session.commit()
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Get a user from a session ID.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate a reset password token for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The generated reset password token.

        Raises:
            ValueError: If no user is found with the given email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"No user found with email '{email}'")

        reset_token = _generate_uuid()
        user.reset_token = reset_token
        self._db._session.commit()
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update user's password using a reset token.

        Args:
            reset_token (str): The reset token associated with the user.
            password (str): The new password to set.

        Returns:
            None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        user.hashed_password = hashed_password
        user.reset_token = None

        self._db._session.commit()
