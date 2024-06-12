#!/usr/bin/env python3
"""
Basic Flask app
"""

from flask import Flask, jsonify, request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def welcome():
    """
    GET route at the root that returns a JSON message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """
    POST route to register a user.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError as err:
        return jsonify({"message": str(err)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
