"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint # type: ignore
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS # type: ignore
# from werkzeug,security import generate_password_hash,check_password_hash # type: ignore

from flask_jwt_extended import create_access_token # type: ignore
from flask_jwt_extended import get_jwt_identity # type: ignore
from flask_jwt_extended import jwt_required # type: ignore

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.


#hice yo sola 
@api.route("/signup", methods=["POST"])
def signup():
    body = request.json
    email = body.get ("email",None)
    password = body.get("password", None)

    if email is None or password is None:
        return jsonify({"error":"se necesita email y password"}),400
    
    # encriptar la contraseña 
    # password_hash = generate_password_hash(password) # type: ignore
    if User.query.filter.by(email=email) is not None:
        return jsonify ({"error": "Email ya tomado"}),400
    
    try: 
        new_user=User (email=email,password=password, is_active=True)
        db.session.add (new_user)
        db.session.commit()

        return jsonify ({"msg":"Usuario creado con exito, Congrats"}),201
    except Exception as error:
        return jsonify({"error", f"{error}"}),500
    




#hasta aca 


@api.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)
