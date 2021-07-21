#based on tut: https://www.youtube.com/watch?v=WxGBoY5iNXY
#Requires SQLite3 to be installed
#linktame_api_main
import sys, os
import datetime
import pytz

import gunicorn
import json #havent used yet
import requests #havent used yet

import uuid #To generate random public_id

from werkzeug.security import generate_password_hash, check_password_hash #To handling hashing passwords

import jwt #PyJWT
import datetime #for jwt token expiration
from functools import wraps #for JWT decorator

from flask import Flask, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
import psycopg2 # needed for heroku PostgreSQL connection
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

#db Config--------------------------------------------------------------------------------------------
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Comment out the following and line 40 for heroku deployment and git push
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\athey\\Documents\\Code\\Linktame-api\\links.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\Richard\\Documents\\Code\\Linktame\\linktame-api\\links.db'
#https://help.heroku.com/ZKNTJQSK/why-is-sqlalchemy-1-4-x-not-connecting-to-heroku-postgres
#Comment out the following line 40 for local deployment,
#"""
import re

uri = "postgres://kdscgqldgfhkkw:55319574f1f8e6ae17c933ad31ac0a0745d12f18d3a19ae9800d9bb40839657c@ec2-107-21-10-179.compute-1.amazonaws.com:5432/dcoseru0ud8gpr"  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
# rest of connection code using the connection string `uri`
# Configure Database
 # this is to point to local url, but for heroku deployment see:https://medium.com/analytics-vidhya/heroku-deploy-your-flask-app-with-a-database-online-d19274a7a749
app.config['SQLALCHEMY_DATABASE_URI'] = uri
# """
# create the db class
db = SQLAlchemy(app)
# Create the two classes that represent the tables in the Database
# User table
class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True) #Public_id is used to help prevent people seeing how many users are in the db
    email = db.Column(db.String(120),unique=True)
    name = db.Column(db.String(120),unique=True, nullable=True) #Optional
    password = db.Column(db.String(120))
    admin = db.Column(db.Boolean,nullable=False,default=False)
    verified = db.Column(db.Boolean,nullable=False,default=False)
    verified_on = db.Column(db.DateTime, nullable=True)
    created_on = db.Column(db.DateTime, nullable=False)
    # Relationship
    links = db.relationship('Links',backref='user')

    def __init__(self, public_id, email, name, password, admin, verified, verified_on, created_on):
        self.public_id = public_id
        self.email = email
        self.name = name
        self.password = password
        self.admin = admin
        self.verified = verified
        self.verified_on = verified_on
        self.created_on = created_on

#Links table
class Links(db.Model):
    __tablename__ = "links"

    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True)
    link = db.Column(db.String)
    link_name = db.Column(db.String(50))
    user_id = db.Column(db.String(50), db.ForeignKey('users.public_id')) #one-many relationship
    link_pos = db.Column(db.Integer)

    def __init__(self, public_id, link, link_name, user_id, link_pos):
        self.public_id = public_id
        self.link = link
        self.link_name = link_name
        self.user_id = user_id
        self.link_pos = link_pos
#db Config--------------------------------------------------------------------------------------------

#JWT token decorator, checks if token is valid
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
        user_data['email'] = user.email
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
        return jsonify({'successful' : False, "message" : "No user found!"}), 200

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
    #Check if Json object has password database
    if not 'password' in data:
        return jsonify({'successful' : False, 'message' : 'Incorrect HTTP body format!'}), 400
    #Hash password
    hashed_password = generate_password_hash(data['password'], method='sha256')
    try:
        #Create new user in db in table Users....use uuid to generate public_id..add timestamp for date created
        new_user = Users(public_id=str(uuid.uuid4()), email=data['email'], name=data['name'], password=hashed_password, admin=False, verified=False, verified_on=None, created_on=datetime.datetime.now(pytz.timezone('Australia/Melbourne')))
        #Check if User already Exists
        already_exists = Users.query.filter_by(email=new_user.email).first()
        if already_exists is not None:
            return jsonify({'successful' : False, 'message' : 'Email already exists!'}), 200
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, 'message' : 'Invalid signup data!'}), 401

    #Create token that is active for timedelta period. datetime needs to be in unix utc timestamp format
    token = jwt.encode({'public_id' : new_user.public_id, 'email' : new_user.email, 'name' : new_user.name, 'exp' : datetime.datetime.now(pytz.timezone('Australia/Melbourne')) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'successful' : True, "message" : "User Created!", 'token' : token}), 200

#Update User Name---------------------------------------------------
#A function that is used to create the users linkta.me.name link
#.name has to be unique
#generates a new JWT token for the user with the name also now embedded
#returns back standard json message of success and message
@app.route('/v1/auth/user', methods=['PUT'])
@token_required #token required decorator
def update_user(current_user):
    #retrieve users public_id from JWT token
    user = Users.query.filter_by(public_id=current_user.public_id).first()
    #check if user exists
    if not user:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #retrieve request body data
    data = request.get_json()
    #check if user name exists in JSON body and retrieve first if so.... much easier way to do this other than try except..Use:
    #if not 'name' in data:
    try:
        name_exists = Users.query.filter_by(name=data['name']).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, 'message' : 'Invalid name!'}), 400

    #Check if name exists
    if not name_exists:
        try:
            user.name = data['name']
            db.session.commit()
        except Exception as e:
            if app_debug:
                print(e)
            return jsonify({'successful' : False, 'message' : 'Invalid name!'}), 400
        #Name inserted successfully
        #Create new JWT token with updated name
        #Create token that is active for timedelta period. datetime needs to be in unix utc timestamp format
        token = jwt.encode({'public_id' : current_user.public_id, 'email' : current_user.email, 'name' : user.name, 'exp' : datetime.datetime.now(pytz.timezone('Australia/Melbourne')) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'name' : user.name, 'successful' : True, "message" : "User name updated!", 'token' : token}), 200
    #Else return Name already exists! 200
    return jsonify({'successful' : False, "message" : "Name already exists!"}), 200

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
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #Promote User to Admin
    user.admin = True
    db.session.commit()

    return jsonify({'successful' : True, "message" : "The user has been promoted!"}), 200

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
        return jsonify({'successful' : False, "message" : "No user found!"}), 200

    db.session.delete(user)
    db.session.commit()

    return jsonify({'successful' : True, "message" : "The user has been deleted!"}), 200

#Handling User endpoints for user managment --------------------------------------------------------

#Handling User endpoints for user authentication --------------------------------------------------------
#login route will work with HTTP basic authentication, all other routes excl /v1/auth/user-POST will work with JWT token in the header
#user logs in with email and password
@app.route('/v1/auth/login', methods=['POST'])
def login():
    #Get authorization data
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        #If auth failed make response returning a 401 with an appropriate header
        return make_response(jsonify({"message" : "Could not verify!", 'successful' : False}), 401 , {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    #if auth info is valid, get user data from db
    email = Users.query.filter_by(email=auth.username).first()
    #Check if user email does not exist
    if not email:
        return make_response(jsonify({"message" : "Could not verify!", 'successful' : False}), 401 , {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    #if user password in db matches user password in auth then generate JWT token
    if check_password_hash(email.password, auth.password):
        #Create token that is active for timedelta period. datetime needs to be in unix utc timestamp format
        token = jwt.encode({'public_id' : email.public_id, 'email' : email.email, 'name' : email.name, 'exp' : datetime.datetime.now(pytz.timezone('Australia/Melbourne')) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'successful' : True, 'token' : token}), 200

    #else if password doesnt match
    return make_response(jsonify({"message" : "Could not verify!", 'successful' : False}), 401 , {'WWW-Authenticate' : 'Basic realm="Login required!"'})

#Link Creation User endpoints for user authentication --------------------------------------------------------
#Endpoint to Create a user link---------------------------------------
#Link position
#Link name
#Link position
@app.route('/v1/user/link', methods=['POST'])
@token_required #token required decorator
def create_link(current_user):
    #This check ensures that the user has not been removed from the Users db but still has a valid JWT token
    try:
        #retrieve users data with public_id from JWT token
        user = Users.query.filter_by(public_id=current_user.public_id).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #This is to check if user actually exists in db ... is redundant
    if not user:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401

    data = request.get_json()

    #Check if Json object has correct data
    for i in range(len(data['links'])):
        if (not 'link' in data['links'][i]) or (not 'link_name' in data['links'][i]) or (not 'link_pos' in data['links'][i]):
            return jsonify({'successful' : False, 'message' : 'Incorrect HTTP body format!'}), 400

    #Add new link to links db
    for i in range(len(data['links'])):
        try:
            new_link = Links(public_id=str(uuid.uuid4()), link=data['links'][i]['link'], link_name=data['links'][i]['link_name'], user_id=user.public_id, link_pos=data['links'][i]['link_pos'])
            db.session.add(new_link)
            db.session.commit()
        except Exception as e:
            if app_debug:
                print(e)
            return jsonify({'successful' : False, 'message' : 'Server error. Check data types!'}), 500

    return jsonify({"message" : "Links Created!", 'successful' : True}), 200

#Endpoint to update a user link---------------------------------------
#NOTE: check if one of the following then update
#Link position
#Link name
#Link position
@app.route('/v1/user/link', methods=['PUT'])
@token_required #token required decorator
def update_link(current_user):
    #This check ensures that the user has not been removed from the Users db but still has a valid JWT token
    try:
        #retrieve users data with public_id from JWT token
        user = Users.query.filter_by(public_id=current_user.public_id).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #This is to check if user actually exists in db ... is redundant
    if not user:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401

    data = request.get_json()

    #Check if Json object has correct data
    if (not 'link' in data) or (not 'link_name' in data) or (not 'link_pos' in data) or (not 'public_id' in data):
        return jsonify({'successful' : False, 'message' : 'Incorrect HTTP body format!'}), 400


    #update links in db
    #delete link in db
    try:
        #query db for public_id
        link = Links.query.filter_by(public_id=data['public_id']).first()
        #check if link exists
        if not link:
            return jsonify({'successful' : False, "message" : "Link does not exist!"}), 200
        #Update Links here
        db.session.query(Links).filter_by(public_id=data['public_id']).update(dict(link=data['link'],link_pos= data['link_pos'],link_name=data['link_name']))
        db.session.commit()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, 'message' : 'Server error. Check data types!'}), 500

    return jsonify({"message" : "Links Updated!", 'successful' : True}), 200

#Endpoint to delete a user link---------------------------------------
#input: JWT: user_id & JSON Body: link_name & link public_id
#return: JSON success and message
@app.route('/v1/user/link', methods=['DELETE'])
@token_required #token required decorator
def delete_link(current_user):
    #This check ensures that the user has not been removed from the Users db but still has a valid JWT token
    try:
        #retrieve users data with public_id from JWT token
        user = Users.query.filter_by(public_id=current_user.public_id).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #This is to check if user actually exists in db ... is redundant
    if not user:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401

    data = request.get_json()
    #Check if Json object has correct data
    if (not 'link_name' in data) or (not 'public_id' in data):
        return jsonify({'successful' : False, 'message' : 'Incorrect HTTP body format!'}), 400

    #delete link in db
    try:
        #query db for public_id
        link = Links.query.filter_by(public_id=data['public_id']).first()
        #check if link exists
        if not link:
            return jsonify({'successful' : False, "message" : "Link does not exist!"}), 200

        db.session.delete(link)
        db.session.commit()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, 'message' : 'Server error. Check data types!'}), 500

    return jsonify({"message" : "Links deleted!", 'successful' : True}), 200

#Endpoint to Load a users links---------------------------------------
#Return a JSON object of:
#Links positions
#Links names
#Links positions
@app.route('/v1/user/link', methods=['GET'])
@token_required #token required decorator
def load_link(current_user):
    #This check ensures that the user has not been removed from the Users db but still has a valid JWT token
    try:
        #retrieve users data with public_id from JWT token
        user = Users.query.filter_by(public_id=current_user.public_id).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #This is to check if user actually exists in db ... is redundant
    if not user:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #get number of associated links to user public_id
    links = Links.query.filter_by(user_id=user.public_id).all()
    if app_debug:
        print("Number of associated links: ", len(links))
        for i in range(len(links)):
            print(links[i].public_id)
    #Load links into JSON object
    links_return = []
    #links_return[0]['link'] = links[i].link
    #links_return.append({})
    #links_return[1]['link'] = links[i].link
    for i in range(len(links)):
        links_return.append({'public_id':links[i].public_id, 'link' : links[i].link, 'link_name':links[i].link_name, 'link_pos':links[i].link_pos})
    if app_debug:
        print(links_return)

    return jsonify({"message" : "Links Loaded!", 'successful' : True, "links" : links_return}), 200

#Endpoint to Load a users links---------------------------------------
#input: JSON - User Name
#Return a JSON object of:
#Links positions
#Links names
#Links positions
#TO DO - Error handling on name
@app.route('/v1/links/<name>', methods=['GET'])
def load_public_links(name):
    #Do error handling on name here... Check if user Exists
    try:
        #Get public_id from Users table via user name
        public_id = Users.query.filter_by(name=name).first()
    except Exception as e:
        if app_debug:
            print(e)
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #This is to check if user actually exists in db ... is redundant
    if not public_id:
        return jsonify({'successful' : False, "message" : "No user found!"}), 401
    #get number of associated links to user public_id
    links = Links.query.filter_by(user_id=public_id.public_id).all()
    if app_debug:
        print("Number of associated links: ", len(links))
        for i in range(len(links)):
            print(links[i].public_id)
    #Load links into JSON object
    links_return = []
    #links_return[0]['link'] = links[i].link
    #links_return.append({})
    #links_return[1]['link'] = links[i].link
    for i in range(len(links)):
        links_return.append({'public_id':links[i].public_id, 'link' : links[i].link, 'link_name':links[i].link_name, 'link_pos':links[i].link_pos})
    if app_debug:
        print(links_return)

    return jsonify({"message" : "Links Loaded!", 'successful' : True, "links" : links_return}), 200

#App Run-----------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
