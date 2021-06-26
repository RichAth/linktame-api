#based on tut: https://www.youtube.com/watch?v=WxGBoY5iNXY
#Requires SQLite3 to be installed
import sys, os

import gunicorn
import json #havent used yet
import requests #havent used yet

import uuid #To generate random public_id

from werkzeug.security import generate_password_hash, check_password_hash #To handling hashing passwords

#from flask_jwt_extended import JWTManager
import jwt
import datetime #for jwt token expiration
from functools import wraps #for JWT decorator

from flask import Flask, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
import psycopg2 #for heroku PostgreSQL connection
#from flask_restful import Api, Resource #...not working after flask update - flask_restful seems to be outdated
from flask_cors import CORS

#Flask
app = Flask(__name__)
#CORS allows for localhost:3000 URL to access API through browser: see CORS
api = CORS(app)
#debugging enables printing to cmd
app_debug = 1
#Secret key to use the encoding of the JWT token
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\athey\\Documents\\Linktame\\links.db'
#https://help.heroku.com/ZKNTJQSK/why-is-sqlalchemy-1-4-x-not-connecting-to-heroku-postgres
import re

uri = "postgres://nhbiopxtnzqwip:7c99441754b6cb896c7a42aa61d8095ee1b1ccc4f3be7d5565e3a6036f50379b@ec2-50-17-255-120.compute-1.amazonaws.com:5432/deo78hf9n71goj"  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
# rest of connection code using the connection string `uri`
#Configure Database
 #this is to point to local url, but for heroku deployment see:https://medium.com/analytics-vidhya/heroku-deploy-your-flask-app-with-a-database-online-d19274a7a749
app.config['SQLALCHEMY_DATABASE_URI'] = uri
#create the db class
db = SQLAlchemy(app)
#Create the two classes that represent the tables in the Database
#User table
class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True) #Public_id is used to help prevent people seeing how many users are in the db
    email = db.Column(db.String(120),unique=True)
    name = db.Column(db.String(120),unique=True, nullable=True) #Optional
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

    def __init__(self, public_id, email, name, password, admin):
        self.public_id = public_id
        self.email = email
        self.name = name
        self.password = password
        self.admin = admin

#Links table
class Links(db.Model):
    __tablename__ = "links"

    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True)
    link = db.Column(db.String)
    link_name = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

    def __init__(self, public_id, link, link_name, user_id):
        self.public_id = public_id
        self.link = link
        self.link_name = link_name
        self.user_id = user_id

#JWT token decorator, checking if token is valid
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        #create empty token
        token = None
        #check and see if theres a header called x-access-token in request.headers if true retrieve token
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}),401
        #try to decode token with try except, if decoding fails then catch except
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            #Query db to see which user the token belongs to
            current_user = Users.query.filter_by(public_id=data['public_id']).first() #can take first record becuse it is unique
        except Exception as e:
            if app_debug:
                print(e)
            return jsonify({'message' : 'Token is invalid!'}),401

        #Token is valid and now have a user. Now passing user into route
        return f(current_user, *args, **kwargs)

    return decorated

#display hmtl page for base URL----------------------------------
@app.route('/')
def home():
   return render_template('home.html')
#Handling User endpoints for users managment --------------------------------------------------------
#Get all Users---------------------------------------------------
@app.route('/v1/auth/user', methods=['GET'])
@token_required #token required decorator to see if valid token
def get_all_users(current_user):
    #check if current user is Admin
    if not current_user.admin:
        return jsonify({"message" : "User does not have admin permissions!"})


    #Query Users table in db
    users = Users.query.all()
    #Cant put sqlite3 query in JSON object directly need to create an onject first
    output = []
    #loop over the users in query results and insert into object
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.name
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)


    return jsonify({'users' : output}), 200
#Get One User--------------------------------------------------
@app.route('/v1/auth/user/<public_id>', methods=['GET'])
@token_required #token required decorator
def get_one_user(current_user, public_id):
    #check if current user is Admin
    if not current_user.admin:
        return jsonify({"message" : "User does not have admin permissions!"})

    #query db for public_id
    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'successful' : 'false', "message" : "No user found!"}), 200

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['email'] = user.name
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data}), 200

#Create User---------------------------------------------------
@app.route('/v1/auth/user', methods=['POST'])
#token not required for /v1/auth/user
def create_user():

    data = request.get_json()
    #Hash password
    hashed_password = generate_password_hash(data['password'], method='sha256')
    try:
        #Create new user in db in table Users....use uuid to generate public_id
        new_user = Users(public_id=str(uuid.uuid4()), email=data['email'], name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : 'false', 'message' : 'Invalid signup data!'}), 400

    #Create token that is active for timedelta period. datetime needs to be in unix utc timestamp format
    token = jwt.encode({'public_id' : new_user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'successful' : 'true', "message" : "User Created!", 'token' : token}), 200

#Update User Name---------------------------------------------------
@app.route('/v1/auth/user', methods=['PUT'])
@token_required #token required decorator
def update_user(current_user):
    #retrieve users public_id from JWT token
    user = Users.query.filter_by(public_id=current_user.public_id).first()
    #check if user exists
    if not user:
        return jsonify({'successful' : 'false', "message" : "No user found!"}), 401

    data = request.get_json()
    #check if user name exists
    name_exists = Users.query.filter_by(name=data['name']).first()
    #Check if name exists
    if not name_exists:
        try:
            user.name = data['name']
            db.session.commit()
        except Exception as e:
            if app_debug:
                print(e)
            return jsonify({'successful' : 'false', 'message' : 'Invalid name!'}), 400
        #Name inserted successfully
        return jsonify({'successful' : 'true', "message" : "User name updated!"}), 200
    #Else return invalid name
    return jsonify({'successful' : 'false', "message" : "Invalid name!"}), 200

#Takes in user_id and will promote any user id to admin thats passed into an admin user_id
@app.route('/v1/auth/user/<public_id>', methods=['PUT'])
@token_required #token required decorator to see if valid token
def promote_user(current_user, public_id):
    #check if current user is Admin
    if not current_user.admin:
        return jsonify({"message" : "User does not have admin permissions!"})

    #query db for public_id
    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'successful' : 'false', "message" : "No user found!"}), 401
    #Promote User to Admin
    user.admin = True
    db.session.commit()

    return jsonify({'successful' : 'true', "message" : "The user has been promoted!"}), 200

#Endpoint to Delete User---------------------------------------
@app.route('/v1/auth/user/<public_id>', methods=['DELETE'])
@token_required #token required decorator to see if valid token
def delete_user(current_user, public_id):
    #check if current user is Admin
    if not current_user.admin:
        return jsonify({"message" : "User does not have admin permissions!"})

    #query db for public_id
    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'successful' : 'false', "message" : "No user found!"}), 200

    db.session.delete(user)
    db.session.commit()

    return jsonify({'successful' : 'true', "message" : "The user has been deleted!"}), 200

#Handling User endpoints for user managment --------------------------------------------------------

#Handling User endpoints for user authentication --------------------------------------------------------
#login route will work with HTTP basic authentication, all other routes excl /v1/auth/user-POST will work with JWT token in the header
#user logs in with email and password
@app.route('/v1/auth/login')
def login():
    #Get authorization data
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        #If auth failed make response returning a 401 with an appropriate header
        return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm="Login required!"'})

    #if auth info is valid, get user data from db
    email = Users.query.filter_by(email=auth.username).first()
    #if user does not exist
    if not email:
        return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm="Login required!"'})
    #if user password in db matches user password in auth then generate JWT token
    if check_password_hash(email.password, auth.password):
        #Create token that is active for timedelta period. datetime needs to be in unix utc timestamp format
        token = jwt.encode({'public_id' : email.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'successful' : 'true', 'token' : token}), 200

    #else if password doesnt match
    return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm="Login required!"'})



#App Run-----------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
