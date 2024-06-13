#!/usr/bin/env python3
"""
Basic Flask app
"""

from flask import Flask, jsonify, request, abort, redirect
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


@app.route('/sessions', methods=['POST'])
def login():
    """
    POST route to log in a user.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'])
def logout():
    """
    DELETE route to logout a user by destroying their session.
    """
    session_id = request.cookies.get('session_id')

    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect('/', code=302)
        else:
            return jsonify({"message": "Forbidden"}), 403
    else:
        return jsonify({"message": "Forbidden"}), 403


@app.route('/profile', methods=['GET'])
def profile():
    """
    GET route to fetch user profile based on session ID.
    """
    session_id = request.cookies.get('session_id')

    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200
        else:
            abort(403)
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'])
def reset_password():
    """
    POST route to initiate password reset.
    """
    email = request.form.get('email')

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError as err:
        abort(403, str(err))


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """
    PUT route to update user's password based on reset token.
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
