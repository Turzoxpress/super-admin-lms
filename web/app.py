import json
import os

from flask import Flask, jsonify, request, make_response, redirect, url_for, flash, render_template, send_from_directory
from flask_restful import Api, Resource, reqparse
from pymongo import MongoClient
import bcrypt

import jwt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import base64
from base64 import b64encode
import PIL
from PIL import Image
import time

import requests

import smtplib
from flask_cors import CORS
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from bson import ObjectId

import geloc

import ssl


app = Flask(__name__)
CORS(app)
api = Api(app)
app.config['JSON_SORT_KEYS'] = False
secret_key = "bangladesh1@4432_1@"

client = MongoClient("mongodb://db:27017")
db = client["SuperAdminDB"]
superad = db["SuperAdmin"]
tokenbank = db["tokenbank"]
packagecol = db["packageCollection"]
institutecol = db["instituteCollection"]
usertypecol = db["userTypeCollection"]
normalusercol = db["normalUserCollection"]
billcol = db["billCollection"]
emailcol = db["emailCollection"]
settingspackagecol = db["settingsPackageCollection"]
settingsinstitutecol = db["settingsInstituteCollection"]

test = db["test"]

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = "."

file_upload_server_path_php = 'https://learnerscafe.com/turzo/upload.php'
file_upload_server_path = 'https://learnerscafe.com/turzo/files/'

ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
ctx.load_cert_chain('certificate.pem', 'privateKey.pem')



# -- Welcome API
class Welcome(Resource):
    def get(self):
        # Show a welcome greetings
        retJson = {
            "status": "ok",
            "msg": "Welcome Turzo! Your Python & MongoDB based API server is working successfully!"
        }
        return jsonify(retJson)


def UserExist(username):
    if superad.find({"email": username}).count() == 0:
        return False
    else:
        return True


def TokenExist(tokenToCheck):
    if tokenbank.find({"token": tokenToCheck}).count() == 0:
        return False
    else:
        return True


def UserExistNormal(username):
    if normalusercol.find({"email": username}).count() == 0:
        return False
    else:
        return True


def UserExistNormalWithMobile(mobile):
    if normalusercol.find({"mobile": mobile}).count() == 0:
        return False
    else:
        return True


# -- Register new super admin
class RegisterSuperAdmin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        password = postedData["password"]
        date_of_joining = postedData["date_of_joining"]
        employee_id = postedData["employee_id"]

        if UserExist(email):
            retJson = {
                'status': 301,
                'msg': 'User already exists,Try with a new one!'
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store username and pw into the database
        superad.insert_one({
            "email": email,
            "password": hashed_pw,
            "role": "Super Admin",
            "date_of_joining": date_of_joining,
            "employee_id": employee_id,
            "created_at": datetime.today().strftime('%d-%m-%Y')

        })

        retJson = {
            "status": "ok",
            "msg": "New Super Admin added successfully!"
        }

        return jsonify(retJson)


def verifyPw(email, password):
    if not UserExist(email):
        return False

    hashed_pw = superad.find({
        "email": email
    })[0]["password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


# -- Show all super admins
class ShowAllSuperAdmin(Resource):
    def get(self):
        # data = superad.find_one()
        # abc = json.dumps(data, sort_keys=True, indent=4, default=json_util.default)
        # return str(abc)

        data = superad.find()
        holder = []
        for i in data:
            holder.append(i)
        retJson = {
            "status": "ok",
            "data": str(holder)
        }

        return jsonify(retJson)


# -- Delete all super admins
class DeleteAllData(Resource):
    def get(self):
        superad.drop()

        retJson = {
            "status": "ok",
            "msg": "All super admin collection data deleted successfully!"
        }

        return jsonify(retJson)


def generateAuthToken(email):
    iat = datetime.utcnow()
    exp = iat + timedelta(days=30)
    nbf = iat
    payload = {
        'exp': exp,
        'iat': iat,
        'nbf': nbf
        # 'aud': str(username)
    }
    if email:
        payload['sub'] = email

    tempData = jwt.encode(
        payload,
        str(secret_key),
        algorithm='HS256'
    ).decode('utf-8')

    return tempData


# -- Super admin login
class SuperAdminLogin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        password = postedData["password"]

        # Check user with email
        if not UserExist(email):
            """retJson = {
                'status': 301,
                'msg': 'No user exist with this username'
            }
            return jsonify(retJson)"""

            ## check another db
            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            # Check password
            if not verifyPwNormal(email, password):
                retJson = {
                    'status': 301,
                    'msg': 'Wrong username or password'
                }
                return jsonify(retJson)

            userid = normalusercol.find({
                "email": email
            })[0]["_id"]

            role = normalusercol.find({
                "email": email
            })[0]["role"]

            date_of_joining = normalusercol.find({
                "email": email
            })[0]["date_of_joining"]

            employee_id = normalusercol.find({
                "email": email
            })[0]["employee_id"]

            # -- Generate an access token
            retJson = {
                'status': 200,
                'msg': {
                    "id": str(userid),
                    "role": str(role),
                    "date_of_joining": str(date_of_joining),
                    "employee_id": str(employee_id),
                    "token": generateAuthToken(email)
                }
            }
            return jsonify(retJson)

            #############################

        # Check password
        if not verifyPw(email, password):
            retJson = {
                'status': 301,
                'msg': 'Wrong username or password'
            }
            return jsonify(retJson)

        userid = superad.find({
            "email": email
        })[0]["_id"]

        role = superad.find({
            "email": email
        })[0]["role"]

        date_of_joining = normalusercol.find({
            "email": email
        })[0]["date_of_joining"]

        employee_id = normalusercol.find({
            "email": email
        })[0]["employee_id"]

        # -- Generate an access token
        retJson = {
            'status': "ok",
            'msg': {
                "id": str(userid),
                "role": str(role),
                "date_of_joining": str(date_of_joining),
                "employee_id": str(employee_id),
                "token": generateAuthToken(email)
            }
        }
        return jsonify(retJson)


def verifyToken():
    auth_header_value = request.headers.get('Authorization', None)

    if not auth_header_value:
        return False

    parts = auth_header_value.split()

    if parts[0].lower() != 'bearer':
        return False
    elif len(parts) == 1:
        return False
    elif len(parts) > 2:
        return False

    # return parts[1]
    temp = jwt.decode(parts[1], str(secret_key), algorithms='HS256')

    retJson = {
        "status": "ok",
        "received_token": parts[1],
        "data": temp
    }

    return jsonify(retJson)


# -- Super admin logout
class SuperAdminLogOut(Resource):
    def get(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            return False

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            return False
        elif len(parts) == 1:
            return False
        elif len(parts) > 2:
            return False

        try:
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            retJson = {
                "status": "ok",
                "msg": "Logout success!"
            }

            return jsonify(retJson)
        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Super Admin Password Update
class UpdateSuperAdminPassword(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # ---------------
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]
            old_password = postedData["old_password"]
            password = postedData["password"]
            password_confirmation = postedData["password_confirmation"]
            if password != password_confirmation:
                retJson = {
                    "status": "failed",
                    "msg": "New password & confirm password does not matched"
                }
                return jsonify(retJson)

            else:

                if not UserExist(email):
                    """retJson = {
                        'status': 301,
                        'msg': 'No user exist with this username'
                    }
                    return jsonify(retJson)"""

                    if not UserExistNormal(email):
                        retJson = {
                            'status': 301,
                            'msg': 'No user exist with this username'
                        }
                        return jsonify(retJson)

                    # return 'Ready to do next job'
                    hashed_pw = normalusercol.find({
                        "email": email
                    })[0]["password"]

                    if bcrypt.hashpw(old_password.encode('utf8'), hashed_pw) == hashed_pw:
                        # return 'Ready to do next job'
                        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

                        myquery = {"email": email}
                        newvalues = {"$set": {
                            "password": hashed_pw,
                            "updated_at": datetime.today().strftime('%d-%m-%Y')
                        }}

                        normalusercol.update_one(myquery, newvalues)

                        retJson = {
                            "status": "ok",
                            "msg": "Password updated"
                        }
                        return jsonify(retJson)

                    else:
                        # return 'Old password is wrong!'
                        retJson = {
                            "status": "failed",
                            "msg": "Old password is wrong!"
                        }
                        return jsonify(retJson)

                # return 'Ready to do next job'
                hashed_pw = superad.find({
                    "email": email
                })[0]["password"]

                if bcrypt.hashpw(old_password.encode('utf8'), hashed_pw) == hashed_pw:
                    # return 'Ready to do next job'
                    hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

                    myquery = {"email": email}
                    newvalues = {"$set": {
                        "password": hashed_pw,
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    superad.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Password updated"
                    }
                    return jsonify(retJson)

                else:
                    # return 'Old password is wrong!'
                    retJson = {
                        "status": "failed",
                        "msg": "Old password is wrong!"
                    }
                    return jsonify(retJson)


        # --------------------------------

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Super Admin Profile Info Update
class SuperAdminProfileInfoUpdate(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            fname = postedData["fname"]
            lname = postedData["lname"]
            mobile = postedData["mobile"]
            date_of_birth = postedData["date_of_birth"]
            place_of_birth = postedData["place_of_birth"]
            gender = postedData["gender"]
            marital_status = postedData["marital_status"]
            nationality = postedData["nationality"]
            nid = postedData["nid"]
            religion = postedData["religion"]
            designation = postedData["designation"]

            date_of_joining = postedData["date_of_joining"]
            employee_id = postedData["employee_id"]

            # Check user with email
            if not UserExist(email):
                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "No user found with this email"
                    }

                    return jsonify(retJson)

                # get the data
                # postedData = request.get_json()

                # Get the data

                myquery = {"email": email}
                newvalues = {"$set": {
                    "username": fname,
                    "fname": fname,
                    "lname": lname,
                    "mobile": mobile,
                    "date_of_birth": date_of_birth,
                    "place_of_birth": place_of_birth,
                    "marital_status": marital_status,
                    "nationality": nationality,
                    "nid": nid,
                    "gender": gender,
                    "religion": religion,
                    "designation": designation,
                    "date_of_joining": date_of_joining,
                    "employee_id": employee_id,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                normalusercol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Profile info updated"
                }
                return jsonify(retJson)

            # get the data
            # postedData = request.get_json()

            # Get the data

            myquery = {"email": email}
            newvalues = {"$set": {
                "username": fname,
                "fname": fname,
                "lname": lname,
                "mobile": mobile,
                "date_of_birth": date_of_birth,
                "place_of_birth": place_of_birth,
                "marital_status": marital_status,
                "nationality": nationality,
                "nid": nid,
                "gender": gender,
                "religion": religion,
                "designation": designation,
                "date_of_joining": date_of_joining,
                "employee_id": employee_id,
                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            superad.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Profile info updated"
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Super Admin profile info
class GetSuperAdminProfileInfo(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            # Check user with email
            if not UserExist(email):
                """retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)"""

                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "Email not found"
                    }

                    return jsonify(retJson)

                result = normalusercol.find({"email": email})
                holder = []
                user_data = {}
                for i in result:
                    # user_data = {}
                    user_data["id"] = str(i["_id"])
                    user_data["username"] = str(i["username"])
                    user_data["email"] = str(i["email"])
                    user_data["avatar_img"] = str(i["avatar_img"])
                    user_data["cover_img"] = str(i["cover_img"])
                    user_data["created_at"] = str(i["created_at"])
                    user_data["fname"] = str(i["fname"])
                    user_data["lname"] = str(i["lname"])
                    user_data["mobile"] = str(i["mobile"])
                    user_data["marital_status"] = str(i["marital_status"])
                    user_data["date_of_birth"] = str(i["date_of_birth"])
                    user_data["place_of_birth"] = str(i["place_of_birth"])
                    user_data["gender"] = str(i["gender"])
                    user_data["religion"] = str(i["religion"])
                    user_data["nationality"] = str(i["nationality"])
                    user_data["nid"] = str(i["nid"])
                    user_data["designation"] = str(i["designation"])
                    user_data["role"] = str(i["role"])

                    user_data["date_of_joining"] = str(i["date_of_joining"])
                    user_data["employee_id"] = str(i["employee_id"])

                    user_data["status"] = str(i["status"])
                    # holder.append(user_data)

                retJson = {
                    "status": "ok",
                    "msg": user_data
                }
                return jsonify(retJson)

            result = superad.find({"email": email})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["username"] = str(i["username"])
                user_data["email"] = str(i["email"])
                user_data["avatar_img"] = str(i["avatar_img"])
                user_data["cover_img"] = str(i["cover_img"])
                user_data["created_at"] = str(i["created_at"])
                user_data["fname"] = str(i["fname"])
                user_data["lname"] = str(i["lname"])
                user_data["mobile"] = str(i["mobile"])
                user_data["marital_status"] = str(i["marital_status"])
                user_data["date_of_birth"] = str(i["date_of_birth"])
                user_data["place_of_birth"] = str(i["place_of_birth"])
                user_data["gender"] = str(i["gender"])
                user_data["religion"] = str(i["religion"])
                user_data["nationality"] = str(i["nationality"])
                user_data["nid"] = str(i["nid"])
                user_data["designation"] = str(i["designation"])
                user_data["role"] = str(i["role"])

                user_data["date_of_joining"] = str(i["date_of_joining"])
                user_data["employee_id"] = str(i["employee_id"])

                user_data["status"] = str(i["status"])
                # holder.append(user_data)

            retJson = {
                "status": "ok",
                "msg": user_data
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Super Admin Address Update
class SuperAdminAddressUpdate(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            # get the data
            postedData = request.get_json()

            # Check user with email
            if not UserExist(email):
                # --------------
                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "Email not found"
                    }

                    return jsonify(retJson)

                # Get the data
                address = postedData["address"]

                per_address = postedData["per_address"]

                myquery = {"email": email}
                newvalues = {"$set": {
                    "address": address,

                    "per_address": per_address,

                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                normalusercol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Address updated"
                }
                return jsonify(retJson)

            # ---------------------------------------------------

            # Get the data
            address = postedData["address"]

            per_address = postedData["per_address"]

            myquery = {"email": email}
            newvalues = {"$set": {
                "address": address,

                "per_address": per_address,

                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            superad.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Address updated"
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Super Admin address
class GetSuperAdminAddress(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            # Check user with email
            if not UserExist(email):
                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "Email not found"
                    }

                    return jsonify(retJson)

                result = normalusercol.find({"email": email})
                holder = []
                user_data = {}
                for i in result:
                    # user_data = {}
                    user_data["id"] = str(i["_id"])
                    user_data["user_id"] = str(i["_id"])
                    user_data["address"] = str(i["address"])

                    user_data["per_address"] = str(i["per_address"])

                    # holder.append(user_data)

                retJson = {
                    "status": "ok",
                    "msg": user_data
                }
                return jsonify(retJson)

            result = superad.find({"email": email})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["user_id"] = str(i["_id"])
                user_data["address"] = str(i["address"])

                user_data["per_address"] = str(i["per_address"])

                # holder.append(user_data)

            retJson = {
                "status": "ok",
                "msg": user_data
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/test', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'avatar_img' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['avatar_img']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({"status": "uploaded"})


app.secret_key = "secret key"


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -- Super Admin avatar image upload
class SuperAdminAvatarImageUpload(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            email = request.form['email']

            # Check user with email
            if not UserExist(email):
                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "User not found with this email"
                    }

                    return jsonify(retJson)

                # work to do
                if request.method == 'POST':
                    attachmentPath = ""

                    ############################ Attachment upload

                    if 'avatar_img' in request.files:
                        file_attachment = request.files['avatar_img']
                        filename = str(time.time_ns()) + "_" + file_attachment.filename
                        file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                        filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                        url = file_upload_server_path_php

                        payload = {'main_url': file_upload_server_path}
                        files = [
                            ('fileToUpload', open(filepath, 'rb'))
                        ]
                        headers = {}

                        response = requests.request("POST", url, headers=headers, data=payload, files=files)
                        # return response.text
                        data = json.loads(response.text)['message']
                        attachmentPath = data
                    else:
                        attachmentPath = ""

                        ############################ end of attachement upload

                        ############################ Image upload

                    # return (str(j1))
                    myquery = {"email": email}
                    newvalues = {"$set": {
                        "avatar_img": attachmentPath,
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    normalusercol.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Avatar image updated",
                        "path": attachmentPath
                    }
                    return jsonify(retJson)

                # work to do
            if request.method == 'POST':
                attachmentPath = ""

                ############################ Attachment upload

                if 'avatar_img' in request.files:
                    file_attachment = request.files['avatar_img']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                    ############################ end of attachement upload

                    ############################ Image upload

                # return (str(j1))
                myquery = {"email": email}
                newvalues = {"$set": {
                    "avatar_img": attachmentPath,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                superad.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Avatar image updated",
                    "path": attachmentPath
                }
                return jsonify(retJson)



        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Super Admin cover image upload
class SuperAdminCoverImageUpload(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            email = request.form['email']

            # Check user with email
            if not UserExist(email):
                if not UserExistNormal(email):
                    retJson = {
                        "status": "failed",
                        "msg": "User no found with this email"
                    }

                    return jsonify(retJson)

                # work to do
                if request.method == 'POST':
                    if 'cover_img' in request.files:
                        file_attachment = request.files['cover_img']
                        filename = str(time.time_ns()) + "_" + file_attachment.filename
                        file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                        filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                        url = file_upload_server_path_php

                        payload = {'main_url': file_upload_server_path}
                        files = [
                            ('fileToUpload', open(filepath, 'rb'))
                        ]
                        headers = {}

                        response = requests.request("POST", url, headers=headers, data=payload, files=files)
                        # return response.text
                        data = json.loads(response.text)['message']
                        attachmentPath = data
                    else:
                        attachmentPath = ""

                        # return data['link']
                        # return (str(j1))
                    myquery = {"email": email}
                    newvalues = {"$set": {
                        "cover_img": attachmentPath,
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    normalusercol.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Cover image updated",
                        "path": attachmentPath
                    }
                    return jsonify(retJson)

                # work to do
            if request.method == 'POST':
                if 'cover_img' in request.files:
                    file_attachment = request.files['cover_img']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                    # return data['link']
                    # return (str(j1))
                myquery = {"email": email}
                newvalues = {"$set": {
                    "cover_img": attachmentPath,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                superad.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Cover image updated",
                    "path": attachmentPath
                }
                return jsonify(retJson)



        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


@app.route('/test2', methods=['POST'])
def upload_image():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'avatar_img' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['avatar_img']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # return jsonify({"status": "uploaded"})
            client_id = 'cc2c0f99f595668'
            headers = {"Authorization": "Client-ID cc2c0f99f595668"}

            api_key = 'b84299a7fc0ab710f3f13b5e91de231f52aa2a22'

            url = "https://api.imgur.com/3/upload.json"
            # im1 = Image.open(file)
            filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            j1 = requests.post(
                url,
                headers=headers,
                data={
                    'key': api_key,
                    'image': b64encode(open(filepath, 'rb').read()),
                    'type': 'base64',
                    'name': '1.jpg',
                    'title': 'Picture no. 1'
                }
            )
            data = json.loads(j1.text)['data']

            return data['link']
            # return (str(j1))


class SuperAdminPasswordResetRequestByEmail(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        # Check user with email
        if not UserExist(email):
            if not UserExistNormal(email):
                retJson = {
                    "status": "failed",
                    "msg": "User not found with this email"
                }

                return jsonify(retJson)

            iat = datetime.utcnow()
            exp = iat + timedelta(days=30)
            nbf = iat
            payload = {
                'exp': exp,
                'iat': iat,
                'nbf': nbf,
                # 'aud': str(email)
            }
            if email:
                payload['sub'] = email

            tempData = jwt.encode(
                payload,
                str(secret_key),
                algorithm='HS256'
            ).decode('utf-8')

            data_to_insert = {"email": email, "token": tempData}

            isTokenInserted = tokenbank.insert_one(data_to_insert)

            url = "http://tuembd.com/test_mail.php?email=" + email + "&token=" + tempData

            payload = {
                'email': email,
                'token': tempData
            }
            headers = {
                'Content-Type': 'application/json'
            }

            # response = requests.request("POST", url, headers=headers, data=payload)

            response = requests.post(
                url,
                headers=headers,
                data={
                    'email': email,
                    'token': tempData
                }
            )
            # data = json.loads(response.text)['data']

            # print(response.text.encode('utf8'))
            retJosn = {
                "status": "ok",
                "msg": tempData,
                "email_status": str(response.text)
                # "tokenStatus": str(isTokenInserted)
            }

            return jsonify(retJosn)

        iat = datetime.utcnow()
        exp = iat + timedelta(days=30)
        nbf = iat
        payload = {
            'exp': exp,
            'iat': iat,
            'nbf': nbf,
            # 'aud': str(email)
        }
        if email:
            payload['sub'] = email

        tempData = jwt.encode(
            payload,
            str(secret_key),
            algorithm='HS256'
        ).decode('utf-8')

        data_to_insert = {"email": email, "token": tempData}

        isTokenInserted = tokenbank.insert_one(data_to_insert)

        url = "http://tuembd.com/test_mail.php?email=" + email + "&token=" + tempData

        payload = {
            'email': email,
            'token': tempData
        }
        headers = {
            'Content-Type': 'application/json'
        }

        # response = requests.request("POST", url, headers=headers, data=payload)

        response = requests.post(
            url,
            headers=headers,
            data={
                'email': email,
                'token': tempData
            }
        )
        # data = json.loads(response.text)['data']

        # print(response.text.encode('utf8'))
        retJosn = {
            "status": "ok",
            "msg": tempData,
            "email_status": str(response.text)
            # "tokenStatus": str(isTokenInserted)
        }

        return jsonify(retJosn)


class SuperAdminPasswordResetReedemByEmail(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        token = postedData["token"]
        password = postedData["password"]
        password_confirmation = postedData["password_confirmation"]

        payload = jwt.decode(token, str(secret_key), algorithms='HS256')
        # return payload['sub']
        which_user = payload['sub']

        # Check user with email
        if not TokenExist(token):
            retJson = {
                "status": "failed",
                "msg": "Password reset token is not valid"
            }

            return jsonify(retJson)

        # Check user with email
        if not UserExist(which_user):
            if not UserExistNormal(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "User not found with this email"
                }

                return jsonify(retJson)

            if password != password_confirmation:
                retJson = {
                    "status": "failed",
                    "msg": "Password & confirm password doesn't matched!"
                }

                return jsonify(retJson)

            """# Check user with email
            if not UserExist(email):
                retJson = {
                    "status": "failed",
                    "msg": "Email not exists"
                }

                return jsonify(retJson)"""

            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

            myquery = {"email": which_user}
            newvalues = {"$set": {
                "password": hashed_pw,
                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            normalusercol.update_one(myquery, newvalues)

            deleteToken = {"token": token}

            isTokenDeleted = tokenbank.delete_one(deleteToken)

            retJson = {
                "status": "ok",
                "msg": "Password reset success"
                # "token_status": str(isTokenDeleted)
            }
            return jsonify(retJson)

        if password != password_confirmation:
            retJson = {
                "status": "failed",
                "msg": "Password & confirm password doesn't matched!"
            }

            return jsonify(retJson)

        """# Check user with email
        if not UserExist(email):
            retJson = {
                "status": "failed",
                "msg": "Email not exists"
            }

            return jsonify(retJson)"""

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        myquery = {"email": which_user}
        newvalues = {"$set": {
            "password": hashed_pw,
            "updated_at": datetime.today().strftime('%d-%m-%Y')
        }}

        superad.update_one(myquery, newvalues)

        deleteToken = {"token": token}

        isTokenDeleted = tokenbank.delete_one(deleteToken)

        retJson = {
            "status": "ok",
            "msg": "Password reset success"
            # "token_status": str(isTokenDeleted)
        }
        return jsonify(retJson)


def PackageExist(packageid):
    if packagecol.find({"_id": packageid}).count() == 0:
        return False
    else:
        return True


def PackageExistWithTitle(title):
    if packagecol.find({"package.title": title}).count() == 0:
        return False
    else:
        return True


# -- Save Package
class PackageSave(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            package = postedData["package"]
            parameters = postedData["parameters"]

            if PackageExistWithTitle(str(package['title'])):
                retJson = {
                    "status": "failed",
                    "msg": "Package name already exists!"
                }

                return jsonify(retJson)

            # finding the dynamic paramerters values
            countT = len(parameters)

            # ----- check package tittle is unique or not

            params = []
            for i in range(countT):
                data = {
                    "_id": ObjectId(),
                    "name": parameters[i]['name'],
                    "quantity": parameters[i]['quantity'],
                    "price": parameters[i]['price'],
                    "created_at": datetime.today().strftime('%d-%m-%Y'),
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }
                params.append(data)

            temp_id = packagecol.insert_one({

                "package": {
                    "display": package['display'],
                    "title": package['title'],
                    "description": package['description'],
                    "type": package['type'],
                    "payable_amount": package['payable_amount'],
                    "monthly_service_charge": package['monthly_service_charge'],
                    "total_amount": package['total_amount'],
                    "discounted_amount": package['discounted_amount'],
                    "created_at": datetime.today().strftime('%d-%m-%Y'),
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                },
                "parameters": params

            }).inserted_id

            retJson = {
                "status": "ok",
                "msg": {
                    "package_id": str(temp_id)

                }
            }

            return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get All Package List
class GetAllPackageList(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = packagecol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "display": str(i["package"]["display"]),
                    "title": str(i["package"]["title"]),
                    "payable_amount": str(i["package"]["payable_amount"]),
                    "monthly_service_charge": str(i["package"]["monthly_service_charge"]),
                    "total_amount": str(i["package"]["total_amount"]),
                    "discounted_amount": str(i["package"]["discounted_amount"]),
                    "description": str(i["package"]["description"]),
                    "created_at": str(i["package"]["created_at"]),
                    "updated_at": str(i["package"]["updated_at"]),
                    "type": str(i["package"]["type"]),
                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": holder
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get All Package List Special
class GetAllPackageListSpecial(Resource):
    def get(self):
        result = packagecol.find({})

        holder = []
        for i in result:
            data = {
                "id": str(i["_id"]),
                "display": str(i["package"]["display"]),
                "title": str(i["package"]["title"]),
                "payable_amount": str(i["package"]["payable_amount"]),
                "monthly_service_charge": str(i["package"]["monthly_service_charge"]),
                "total_amount": str(i["package"]["total_amount"]),
                "discounted_amount": str(i["package"]["discounted_amount"]),
                "description": str(i["package"]["description"]),
                "created_at": str(i["package"]["created_at"]),
                "updated_at": str(i["package"]["updated_at"]),
                "type": str(i["package"]["type"]),
            }

            holder.append(data)

        retJson = {
            "status": "ok",
            "msg": holder
        }

        return jsonify(retJson)


# -- Add package missing fields
class AddPackageMissingFields(Resource):
    def get(self):
        try:
            # *******************************************
            # *******************************************

            data = packagecol.find()

            for i in data:
                myquery = {"_id": ObjectId(i["_id"])}
                newvalues = {"$set": {
                    "package.monthly_service_charge": "800",
                    "package.total_amount": "12800",
                    "package.discounted_amount": "800"
                }}

                packagecol.update_one(myquery, newvalues)

            data2 = packagecol.find()
            holder2 = []
            for i in data2:
                holder2.append(i)

            retJson = {
                "status": "ok",
                "msg": str(holder2)
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Task was failed"
            }

            return jsonify(retJson)


# -- Delete package collection
class DeleteFullPackage(Resource):
    def get(self):
        packagecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All package collection data deleted successfully!"
        }

        return jsonify(retJson)


# -- Get Package Details
class GetPackageDetails(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["package_id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not PackageExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Invalid package id"
                    }

                    return jsonify(retJson)

                result = packagecol.find({"_id": ObjectId(id)})

                parameters = {}
                for i in result:
                    parameters = i["parameters"]

                params = []
                for i in parameters:
                    data = {
                        "param_id": str(i["_id"]),
                        "name": str(i["name"]),
                        "quantity": str(i["quantity"]),
                        "price": str(i["price"]),
                        "created_at": str(i["created_at"]),
                        "updated_at": str(i["updated_at"])
                    }
                    params.append(data)

                result2 = packagecol.find({"_id": ObjectId(id)})
                holder = []
                package_data = {}

                for i in result2:
                    package_data["id"] = str(i["_id"])
                    package_data["display"] = str(i["package"]["display"])
                    package_data["title"] = str(i["package"]["title"])
                    package_data["description"] = str(i["package"]["description"])
                    package_data["created_at"] = str(i["package"]["created_at"])
                    package_data["updated_at"] = str(i["package"]["updated_at"])
                    package_data["type"] = str(i["package"]["type"])
                    package_data["payable_amount"] = str(i["package"]["payable_amount"])
                    package_data["monthly_service_charge"] = str(i["package"]["monthly_service_charge"])
                    package_data["total_amount"] = str(i["package"]["total_amount"])
                    package_data["discounted_amount"] = str(i["package"]["discounted_amount"])
                    package_data["params"] = params
                    holder.append(package_data)

                retJson = {
                    "status": "ok",
                    "msg": package_data
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Package Details Special API
class GetPackageDetailsSpecial(Resource):
    def post(self):

        postedData = request.get_json()

        # Get the data
        id = postedData["package_id"]
        special_key = postedData["special_key"]

        if special_key != "super_admin_lms_2020":
            retJson = {
                "status": "failed",
                "msg": "Invalid special key"
            }
            return jsonify(retJson)

        # Check id is valid or not
        if ObjectId.is_valid(id):

            # Check id is exist
            if not PackageExist(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)

            result = packagecol.find({"_id": ObjectId(id)})

            parameters = {}
            for i in result:
                parameters = i["parameters"]

            params = []
            for i in parameters:
                data = {
                    "param_id": str(i["_id"]),
                    "name": str(i["name"]),
                    "quantity": str(i["quantity"]),
                    "price": str(i["price"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])
                }
                params.append(data)

            result2 = packagecol.find({"_id": ObjectId(id)})
            holder = []
            package_data = {}
            for i in result2:
                package_data["id"] = str(i["_id"])
                package_data["display"] = str(i["package"]["display"])
                package_data["title"] = str(i["package"]["title"])
                package_data["description"] = str(i["package"]["description"])
                package_data["created_at"] = str(i["package"]["created_at"])
                package_data["updated_at"] = str(i["package"]["updated_at"])
                package_data["type"] = str(i["package"]["type"])
                package_data["payable_amount"] = int(i["package"]["payable_amount"])
                package_data["monthly_service_charge"] = str(i["package"]["monthly_service_charge"])
                package_data["total_amount"] = str(i["package"]["total_amount"])
                package_data["discounted_amount"] = str(i["package"]["discounted_amount"])
                package_data["params"] = params
                holder.append(package_data)

            retJson = {
                "status": "ok",
                "msg": package_data
            }

            return jsonify(retJson)


        else:
            retJson = {
                "status": "failed",
                "msg": "Invalid package id"
            }

            return jsonify(retJson)


# -- Package Update
class PackageUpdate(Resource):
    def post(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            ################################################################

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            title = postedData["title"]
            display = postedData["display"]
            description = postedData["description"]
            payable_amount = postedData["payable_amount"]
            monthly_service_charge = postedData["monthly_service_charge"]
            total_amount = postedData["total_amount"]
            discounted_amount = postedData["discounted_amount"]

            """if PackageExistWithTitle(title):
                retJson = {
                    "status": "failed",
                    "msg": "Package name already exists!"
                }

                return jsonify(retJson)"""

            parameters = postedData["parameters"]

            countT = len(parameters)

            params = []
            for i in range(countT):
                data = {
                    "_id": ObjectId(),
                    "name": parameters[i]['name'],
                    "quantity": parameters[i]['quantity'],
                    "price": parameters[i]['price'],
                    "created_at": datetime.today().strftime('%d-%m-%Y'),
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }
                params.append(data)

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not PackageExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Package update failed"
                    }

                    return jsonify(retJson)

                myquery = {"_id": ObjectId(id)}
                newvalues = {"$set": {
                    "package.title": title,
                    "package.display": display,
                    "package.description": description,
                    "package.payable_amount": payable_amount,
                    "package.monthly_service_charge": monthly_service_charge,
                    "package.total_amount": total_amount,
                    "package.discounted_amount": discounted_amount,
                    "package.updated_at": datetime.today().strftime('%d-%m-%Y'),
                    "parameters": params
                }}

                packagecol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Package updated successfully"
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Package update failed"
                }

                return jsonify(retJson)

            ##################################################################


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }


def IsPackageUsedForInstitute(package_id):
    if institutecol.find({"package_id": package_id}).count() == 0:
        return True
    else:
        return False


# -- Package Delete
class PackageDelete(Resource):
    def post(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            ################################################################

            postedData = request.get_json()

            # Get the data
            id = postedData["package_id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not PackageExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Package not found"
                    }

                    return jsonify(retJson)

                # Check id is exist
                if not IsPackageUsedForInstitute(id):
                    retJson = {
                        "status": "failed",
                        "msg": "Package already used!"
                    }

                    return jsonify(retJson)

                myquery = {"_id": ObjectId(id)}

                res = packagecol.delete_one(myquery)

                retJson = {
                    "status": "ok",
                    "msg": "Package deleted successfully"
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Package update failed"
                }

                return jsonify(retJson)

            ##################################################################


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }


# -- Package new parameter add
class PackageAddNewParameter(Resource):
    def post(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            ################################################################

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            parameters = postedData["parameters"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not PackageExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Package update failed"
                    }

                    return jsonify(retJson)

                    # to do

                    # finding the dynamic paramerters values
                countT = len(parameters)

                params = []
                for i in range(countT):
                    data = {
                        "_id": ObjectId(),
                        "name": parameters[i]['name'],
                        "quantity": parameters[i]['quantity'],
                        "price": parameters[i]['price'],
                        "created_at": datetime.today().strftime('%d-%m-%Y'),
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }
                    params.append(data)

                result = packagecol.find({"_id": ObjectId(id)})

                """dbparams = {}
                for i in result:
                    dbparams = i["parameters"]

                for i in dbparams:
                    data = {
                        "_id": str(i["_id"]),
                        "name": str(i["name"]),
                        "quantity": str(i["quantity"]),
                        "price": str(i["price"]),
                        "created_at": str(i["created_at"]),
                        "updated_at": str(i["updated_at"])
                    }
                    params.append(data)"""

                myquery = {"_id": ObjectId(id)}

                newvalues = {"$set": {
                    "parameters": params
                }}

                stat = packagecol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Package updated successfully",
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Package update failed"
                }

                return jsonify(retJson)

            ##################################################################


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }


# -- Parameter list according to Package id
class GetPackageParameterList(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["package_id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not PackageExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Invalid package id"
                    }

                    return jsonify(retJson)

                result = packagecol.find({"_id": ObjectId(id)})

                parameters = {}
                for i in result:
                    parameters = i["parameters"]

                params = []
                for i in parameters:
                    data = {
                        "id": str(i["_id"]),
                        "name": str(i["name"]),
                        "quantity": str(i["quantity"]),
                        "price": str(i["price"]),
                        "package_id": str(id),
                        "created_at": str(i["created_at"]),
                        "updated_at": str(i["updated_at"])
                    }
                    params.append(data)

                retJson = {
                    "status": "ok",
                    "msg": params
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Parameter list according to Package id Special API
class GetPackageParameterListSpecial(Resource):
    def post(self):

        postedData = request.get_json()

        # Get the data
        id = postedData["package_id"]
        special_key = postedData["special_key"]

        if special_key != "super_admin_lms_2020":
            retJson = {
                "status": "failed",
                "msg": "Invalid special key"
            }
            return jsonify(retJson)

        # Check id is valid or not
        if ObjectId.is_valid(id):

            # Check id is exist
            if not PackageExist(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)

            result = packagecol.find({"_id": ObjectId(id)})

            parameters = {}
            for i in result:
                parameters = i["parameters"]

            params = []
            for i in parameters:
                data = {
                    "id": str(i["_id"]),
                    "name": str(i["name"]),
                    "quantity": str(i["quantity"]),
                    "price": str(i["price"]),
                    "package_id": str(id),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])
                }
                params.append(data)

            retJson = {
                "status": "ok",
                "msg": params
            }

            return jsonify(retJson)


        else:
            retJson = {
                "status": "failed",
                "msg": "Invalid package id"
            }

            return jsonify(retJson)


def InstituteExistId(id):
    if institutecol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


def InstituteExist(institute_id):
    if institutecol.find({"institute_id": institute_id}).count() == 0:
        return True
    else:
        return False


def SpecialInstituteID():
    previous_id = institutecol.count()
    present_id = previous_id + 1
    return present_id


def InstituteExistWithEmail(email):
    if institutecol.find({"email": email}).count() == 0:
        return True
    else:
        return False


def InstituteExistWithPhone(phone):
    if institutecol.find({"phone": phone}).count() == 0:
        return True
    else:
        return False


# -- Create institute
class InstituteCreate(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            package_id = postedData["package_id"]
            institute_id = postedData["institute_id"]
            password = postedData["password"]
            name = postedData["name"]
            address = postedData["address"]
            email = postedData["email"]
            phone = postedData["phone"]
            subscription_s_date = postedData["subscription_s_date"]
            subscription_e_date = postedData["subscription_e_date"]
            last_payment = postedData["last_payment"]
            payment_amount = postedData["payment_amount"]

            # to do
            # Check id is exist
            if not PackageExist(ObjectId(package_id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)

            if not InstituteExist(institute_id):
                retJson = {
                    "status": "validationError",
                    "msg": {
                        "institute_id": [
                            "The institute id has already been taken."
                        ]
                    }
                }

                return jsonify(retJson)

            if not InstituteExistWithEmail(email):
                retJson = {
                    "status": "failed",
                    "msg": "Email already exists!"
                }

                return jsonify(retJson)

            if not InstituteExistWithPhone(phone):
                retJson = {
                    "status": "failed",
                    "msg": "Phone number already exists!"
                }

                return jsonify(retJson)

            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

            # Store username and pw into the database
            sts = institutecol.insert_one({
                "integer_id": SpecialInstituteID(),
                "package_id": package_id,
                "institute_id": institute_id,
                "password": hashed_pw,
                "name": name,
                "address": address,
                "email": email,
                "phone": phone,
                "subscription_s_date": subscription_s_date,
                "subscription_e_date": subscription_e_date,
                "last_payment": last_payment,
                "payment_amount": payment_amount,
                "created_at": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y'),
                "active": 1

            }).inserted_id

            res = institutecol.find({"_id": ObjectId(sts)})
            int_id = 0;
            for i in res:
                int_id = str(i["integer_id"])

            retJson = {
                "status": "ok",
                "msg": str(sts),
                "integer_id": int(int_id)

            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Create institute Special Main Site
class InstituteCreateSpecial(Resource):
    def post(self):

        postedData = request.get_json()

        # Get the data
        package_id = postedData["package_id"]
        institute_type = postedData["institute_type"]
        institute_name = postedData["institute_name"]
        # institute_id = postedData["institute_id"]
        password = postedData["password"]
        name = postedData["name"]
        address = postedData["address"]
        email = postedData["email"]
        phone = postedData["phone"]
        subscription_s_date = postedData["subscription_s_date"]
        subscription_e_date = postedData["subscription_e_date"]
        last_payment = postedData["last_payment"]
        payment_amount = postedData["payment_amount"]

        # ---
        part1 = ""
        part2 = ""
        part3 = ""

        """"if institute_type == "University":
            part1 = "UNIV"
        elif institute_type == "College":
            part1 = "COL"
        elif institute_type == "School":
            part1 = "SCH"
        elif institute_type == "Madhrasha":
            part1 = "MAD"
        elif institute_type == "Private Training Center":
            part1 = "PTC"""""

        # ------
        words = institute_name.split()
        for i in words:
            if i != "and"  and i != "of" and i != "&" and i != "AND" and i != "OF":
                part2 = part2 + i[0]

        now = datetime.now()
        part3 = now.strftime("%I%M%S")
        institute_id = institute_type + "-" + part2 + "-" + part3
        institute_id = institute_id.upper()

        # ----------------

        # to do
        # Check id is exist
        if not PackageExist(ObjectId(package_id)):
            retJson = {
                "status": "failed",
                "msg": "Invalid package id"
            }

            return jsonify(retJson)

        if not InstituteExist(institute_id):
            retJson = {
                "status": "validationError",
                "msg": {
                    "institute_id": [
                        "The institute id has already been taken."
                    ]
                }
            }

            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store username and pw into the database
        sts = institutecol.insert_one({
            "integer_id": SpecialInstituteID(),
            "package_id": package_id,
            "institute_id": institute_id,
            "password": hashed_pw,
            "name": name,
            "address": address,
            "email": email,
            "phone": phone,
            "subscription_s_date": subscription_s_date,
            "subscription_e_date": subscription_e_date,
            "last_payment": last_payment,
            "payment_amount": payment_amount,
            "created_at": datetime.today().strftime('%d-%m-%Y'),
            "updated_at": datetime.today().strftime('%d-%m-%Y'),
            "active": 1

        }).inserted_id

        res = institutecol.find({"_id": ObjectId(sts)})
        int_id = 0
        for i in res:
            int_id = str(i["integer_id"])

        # -----Last task

        url = "https://lms.learnerscafe.com/api/other/user"

        payload = {
            "firstName": institute_name,
            "email": email,
            "mobile": phone,
            "username": institute_id,
            "password": password,
            "instituteId": int_id
        }
        headers = {
            'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, json=payload,verify=False)
        data = json.loads(response.text)['status']

        # -----------------------------

        if data == "ok":
            retJson = {
                "status": "ok",
                "msg": "Institute created successfully",
                "username": institute_id,
                "password": password,
                "institute_id_super_admin_module": str(sts),
                "institute_id_normal_admin_module": int_id,
                "response_from_normal_admin_module": data

            }

            return jsonify(retJson)
        else:
            retJson = {
                "status": "failed",
                "msg": "Failed to create institute",
                "Details": "Unable to create institute in Admin module",
                "response_from_normal_admin_module": data

            }

            return jsonify(retJson)


# -- Delete institute collection
class DeleteFullInstituteCollection(Resource):
    def get(self):
        institutecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All institute collection data deleted successfully!"
        }

        return jsonify(retJson)


# -- Create update
class InstituteUpdate(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            package_id = postedData["package_id"]
            institute_id = postedData["institute_id"]
            password = postedData["password"]
            name = postedData["name"]
            address = postedData["address"]
            email = postedData["email"]
            phone = postedData["phone"]
            subscription_s_date = postedData["subscription_s_date"]
            subscription_e_date = postedData["subscription_e_date"]
            last_payment = postedData["last_payment"]
            payment_amount = postedData["payment_amount"]

            # to do
            # Check id is exist
            if not PackageExist(ObjectId(package_id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid package id"
                }

                return jsonify(retJson)

            if not InstituteExistId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Institute update failed"
                }

                return jsonify(retJson)

            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "package_id": package_id,
                "institute_id": institute_id,
                "password": hashed_pw,
                "name": name,
                "address": address,
                "email": email,
                "phone": phone,
                "subscription_s_date": subscription_s_date,
                "subscription_e_date": subscription_e_date,
                "last_payment": last_payment,
                "payment_amount": payment_amount,
                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            sts = institutecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Institute updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Institute Details
class GetInstituteDetails(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["institute_id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not InstituteExistId(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Institute id not found"
                    }

                    return jsonify(retJson)

                result = institutecol.find({"_id": ObjectId(id)})
                package_id_db = ""
                package_data = {}
                for i in result:
                    package_data["id"] = id
                    package_data["active"] = str(i["active"])
                    package_data["institute_id"] = str(i["institute_id"])
                    package_data["password"] = str(i["password"])
                    package_data["name"] = str(i["name"])
                    package_data["address"] = str(i["address"])
                    package_data["email"] = str(i["email"])
                    package_data["phone"] = str(i["phone"])
                    package_data["subscription_s_date"] = str(i["subscription_s_date"])
                    package_data["subscription_e_date"] = str(i["subscription_e_date"])
                    package_data["last_payment"] = str(i["last_payment"])
                    package_data["payment_amount"] = str(i["payment_amount"])
                    package_data["created_at"] = str(i["created_at"])
                    package_data["updated_at"] = str(i["updated_at"])

                    # to do
                    package_data["package_id"] = str(i["package_id"])

                    package_id_db = str(i["package_id"])
                    # package_data["package_title"] = "NSU package"
                    # package_data["package_desc"] = "NSU package for summer semester"

                result2 = packagecol.find({"_id": ObjectId(package_id_db)})

                for i in result2:
                    package_data["package_title"] = str(i["package"]["title"])
                    package_data["package_desc"] = str(i["package"]["description"])

                retJson = {
                    "status": "ok",
                    "msg": package_data
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid institute id"
                }

                return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Institute Details Special API
class GetInstituteDetailsSpecial(Resource):
    def post(self):

        postedData = request.get_json()

        # Get the data
        id = postedData["institute_id"]
        special_key = postedData["special_key"]

        if special_key != "super_admin_lms_2020":
            retJson = {
                "status": "failed",
                "msg": "Invalid special key"
            }
            return jsonify(retJson)

        result = institutecol.find({"integer_id": id})
        package_id_db = ""
        package_data = {}
        for i in result:
            package_data["id"] = int(i["integer_id"])
            package_data["active"] = str(i["active"])
            package_data["institute_id"] = str(i["institute_id"])
            package_data["password"] = str(i["password"])
            package_data["name"] = str(i["name"])
            package_data["address"] = str(i["address"])
            package_data["email"] = str(i["email"])
            package_data["phone"] = str(i["phone"])
            package_data["subscription_s_date"] = str(i["subscription_s_date"])
            package_data["subscription_e_date"] = str(i["subscription_e_date"])
            package_data["last_payment"] = str(i["last_payment"])
            package_data["payment_amount"] = str(i["payment_amount"])
            package_data["created_at"] = str(i["created_at"])
            package_data["updated_at"] = str(i["updated_at"])

            # to do
            package_data["package_id"] = str(i["package_id"])

            package_id_db = str(i["package_id"])
            # package_data["package_title"] = "NSU package"
            # package_data["package_desc"] = "NSU package for summer semester"

        result2 = packagecol.find({"_id": ObjectId(package_id_db)})

        for i in result2:
            package_data["package_title"] = str(i["package"]["title"])
            package_data["package_desc"] = str(i["package"]["description"])

        retJson = {
            "status": "ok",
            "msg": package_data
        }

        return jsonify(retJson)


def getPackageNameFromID(id):
    name = packagecol.find({
        "_id": id
    })[0]["package"]["title"]
    return name  # packagecol.find({"package_id": "5fabc454007fe638b25b5307"})[0]["package"]["title"]


# -- Get All Institute List
class GetAllInstituteList(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = institutecol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "active": str(i["active"]),
                    "institute_id": str(i["institute_id"]),
                    "password": str(i["password"]),
                    "name": str(i["name"]),
                    "address": str(i["address"]),
                    "email": str(i["email"]),
                    "phone": str(i["phone"]),
                    "subscription_s_date": str(i["subscription_s_date"]),
                    "subscription_e_date": str(i["subscription_e_date"]),
                    "last_payment": str(i["last_payment"]),
                    "payment_amount": str(i["payment_amount"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"]),
                    "package_id": str(i["package_id"]),
                    "integer_id": int(i["integer_id"]),
                    "package_name": getPackageNameFromID(ObjectId(i["package_id"]))

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "current_page": 1,
                    "data": holder
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get All Institute List Special
class GetAllInstituteListSpecial(Resource):
    def get(self):
        result = institutecol.find({})

        holder = []
        for i in result:
            data = {
                "id": int(i["integer_id"]),
                "active": str(i["active"]),
                "institute_id": str(i["institute_id"]),
                "password": str(i["password"]),
                "name": str(i["name"]),
                "address": str(i["address"]),
                "email": str(i["email"]),
                "phone": str(i["phone"]),
                "subscription_s_date": str(i["subscription_s_date"]),
                "subscription_e_date": str(i["subscription_e_date"]),
                "last_payment": str(i["last_payment"]),
                "payment_amount": str(i["payment_amount"]),
                "created_at": str(i["created_at"]),
                "updated_at": str(i["updated_at"]),
                "package_id": str(i["package_id"])
            }

            holder.append(data)

        retJson = {
            "status": "ok",
            "msg": {
                "current_page": 1,
                "data": holder
            }
        }

        return jsonify(retJson)


# -- Institute API for dashbaord
class InstituteAPIForDashboard(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = institutecol.find({})

            university = 0
            college = 0
            school = 0
            madrasha = 0
            others = 0
            total = 0;

            holder = []
            for i in result:

                total = total + 1
                name = str(i["institute_id"])
                if "UNI" in name:
                    university = university + 1
                elif "COL" in name:
                    college = college + 1
                elif "SCH" in name:
                    school = school + 1
                elif "MAD" in name:
                    madrasha = madrasha + 1
                else:
                    others = others + 1

            retJson = {
                "status": "ok",
                "data": {
                    "total": total,
                    "university": university,
                    "college": college,
                    "school": school,
                    "madrasha": madrasha,
                    "others": others
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Change institute active status
class InstituteActiveStatusChange(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            active = postedData["active"]

            # to do

            if not InstituteExistId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Institute status update failed"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            sts = institutecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Institute status updated"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Institute Delete
class InstituteDelete(Resource):
    def post(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            ################################################################

            postedData = request.get_json()

            # Get the data
            id = postedData["institute_id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not InstituteExist(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Institute delete failed or invalid id"
                    }

                    return jsonify(retJson)

                myquery = {"_id": ObjectId(id)}

                res = institutecol.delete_one(myquery)

                retJson = {
                    "status": "ok",
                    "msg": "Institute deleted successfully"
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Institute delete failed or invalid id"
                }

                return jsonify(retJson)

            ##################################################################


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }


def TypeExist(typename):
    if usertypecol.find({"typename": typename}).count() == 0:
        return False
    else:
        return True


def TypeExistWithId(id):
    if usertypecol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


# ----------------------------------------------------------------------
# -- Create New User Type
class CreateUserType(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            typename = postedData["typename"]
            active = postedData["active"]
            user = postedData["user"]
            institute = postedData["institute"]
            package = postedData["package"]
            bill = postedData["bill"]
            payment = postedData["payment"]

            if TypeExist(typename):
                retJson = {
                    'status': 301,
                    'msg': 'User type already exists!'
                }
                return jsonify(retJson)

            # Store New Type into the database
            usertypecol.insert_one({
                "typename": typename,
                "active": active,
                "user": user,
                "institute": institute,
                "package": package,
                "bill": bill,
                "payment": payment,
                "created_at": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y')
            })

            retJson = {
                "status": "ok",
                "msg": "New User Type added successfully!"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete User Type Collection
class DeleteUserType(Resource):
    def get(self):
        usertypecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All User Type Collection data deleted successfully!"
        }

        return jsonify(retJson)


# -- Get User Type List
class GetUserTypeList(Resource):
    def get(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = usertypecol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "typename": str(i["typename"]),
                    "active": str(i["active"]),
                    "user": str(i["user"]),
                    "institute": str(i["institute"]),
                    "package": str(i["package"]),
                    "bill": str(i["bill"]),
                    "payment": str(i["payment"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- View Single User Type
class ViewSingleUserType(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            # Get the data
            id = postedData["id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not TypeExistWithId(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "User Type with this id not found"
                    }

                    return jsonify(retJson)

                result = usertypecol.find({"_id": ObjectId(id)})
                package_id_db = ""
                package_data = {}
                for i in result:
                    package_data["id"] = id
                    package_data["typename"] = str(i["typename"])
                    package_data["active"] = str(i["active"])
                    package_data["user"] = str(i["user"])
                    package_data["institute"] = str(i["institute"])
                    package_data["package"] = str(i["package"])
                    package_data["bill"] = str(i["bill"])
                    package_data["payment"] = str(i["payment"])
                    package_data["created_at"] = str(i["created_at"])
                    package_data["updated_at"] = str(i["updated_at"])

                retJson = {
                    "status": "ok",
                    "msg": package_data
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid user type id"
                }

                return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update user type
class UpdateUserType(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            user = postedData["user"]
            institute = postedData["institute"]
            package = postedData["package"]
            bill = postedData["bill"]
            payment = postedData["payment"]

            # Check id is exist
            if not TypeExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "User Type with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "user": user,
                "institute": institute,
                "package": package,
                "bill": bill,
                "payment": payment,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = usertypecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "User Type updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update user active type
class UpdateUserActivation(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            active = postedData["active"]

            # Check id is exist
            if not TypeExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "User Type with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = usertypecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "User Type updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Register new normal user
class RegisterNewUserNormal(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        fname = postedData["fname"]
        lname = postedData["lname"]
        email = postedData["email"]
        mobile = postedData["mobile"]
        username = postedData["username"]
        role = postedData["role"]
        password = postedData["password"]
        date_of_birth = postedData["date_of_birth"]
        gender = postedData["gender"]

        date_of_joining = postedData["date_of_joining"]
        employee_id = postedData["employee_id"]

        if UserExist(email):
            retJson = {
                'status': 301,
                'msg': 'Email already exists. Try Again!'
            }
            return jsonify(retJson)

        if UserExistNormal(email):
            retJson = {
                'status': 301,
                'msg': 'Email already exists. Try Again!'
            }
            return jsonify(retJson)

        if UserExistNormalWithMobile(mobile):
            retJson = {
                'status': 301,
                'msg': 'Mobile no. already exists. Try Again!'
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store username and pw into the database
        normalusercol.insert_one({
            "email": email,
            "password": hashed_pw,
            "role": role,
            "created_at": datetime.today().strftime('%d-%m-%Y'),

            "username": username,
            "fname": fname,
            "lname": lname,
            "mobile": mobile,
            "date_of_birth": date_of_birth,
            "place_of_birth": "",
            "marital_status": "",
            "nationality": "",
            "nid": "",
            "gender": gender,
            "religion": "",
            "designation": "",

            "address": "",
            "post_office": "",
            "post_code": "",
            "thana": "",
            "district": "",
            "division": "",
            "per_address": "",
            "per_post_office": "",
            "per_post_code": "",
            "per_thana": "",
            "per_district": "",
            "per_division": "",

            "avatar_img": "",
            "cover_img": "",

            "date_of_joining": date_of_joining,
            "employee_id": employee_id,

            "status": 1,

            "updated_at": datetime.today().strftime('%d-%m-%Y')

        })

        retJson = {
            "status": "ok",
            "msg": "New user created successfully!"
        }

        return jsonify(retJson)


def verifyPwNormal(email, password):
    if not UserExistNormal(email):
        return False

    hashed_pw = normalusercol.find({
        "email": email
    })[0]["password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


# -- Get All User List
class GetAllUserNormalList(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = normalusercol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "email": str(i["email"]),
                    "password": str(i["password"]),
                    "role": str(i["role"]),
                    "created_at": str(i["created_at"]),
                    "username": str(i["username"]),
                    "fname": str(i["fname"]),
                    "lname": str(i["lname"]),
                    "mobile": str(i["mobile"]),
                    "date_of_birth": str(i["date_of_birth"]),
                    "place_of_birth": str(i["place_of_birth"]),
                    "marital_status": str(i["marital_status"]),
                    "nationality": str(i["nationality"]),
                    "nid": str(i["nid"]),
                    "gender": str(i["gender"]),

                    "date_of_joining": str(i["date_of_joining"]),
                    "employee_id": str(i["employee_id"]),

                    "religion": str(i["religion"]),
                    "designation": str(i["designation"]),
                    "address": str(i["address"]),

                    "per_address": str(i["per_address"]),

                    "avatar_img": str(i["avatar_img"]),
                    "cover_img": str(i["cover_img"]),

                    "status": str(i["status"]),

                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": holder
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal user login
class NormalUserLogin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        password = postedData["password"]

        # Check user with email
        if not UserExistNormal(email):
            retJson = {
                'status': 301,
                'msg': 'No user exist with this username'
            }
            return jsonify(retJson)

        # Check password
        if not verifyPwNormal(email, password):
            retJson = {
                'status': 301,
                'msg': 'Wrong username or password'
            }
            return jsonify(retJson)

        userid = normalusercol.find({
            "email": email
        })[0]["_id"]

        # -- Generate an access token
        retJson = {
            'status': 200,
            'msg': {
                "id": str(userid),
                "token": generateAuthToken(email)
            }
        }
        return jsonify(retJson)


# -- Normal User Password Update
class UpdateNormalUserPassword(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # ---------------
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            postedData = request.get_json()

            # Get the data
            email = postedData["email"]
            old_password = postedData["old_password"]
            password = postedData["password"]
            password_confirmation = postedData["password_confirmation"]
            if password != password_confirmation:
                retJson = {
                    "status": "failed",
                    "msg": "New password & confirm password does not matched"
                }
                return jsonify(retJson)

            else:

                # Check user with email
                if not UserExistNormal(email):
                    retJson = {
                        'status': 301,
                        'msg': 'No user exist with this username'
                    }
                    return jsonify(retJson)

                # return 'Ready to do next job'
                hashed_pw = normalusercol.find({
                    "email": email
                })[0]["password"]

                if bcrypt.hashpw(old_password.encode('utf8'), hashed_pw) == hashed_pw:
                    # return 'Ready to do next job'
                    hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

                    myquery = {"email": which_user}
                    newvalues = {"$set": {
                        "password": hashed_pw,
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    normalusercol.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Password updated"
                    }
                    return jsonify(retJson)

                else:
                    # return 'Old password is wrong!'
                    retJson = {
                        "status": "failed",
                        "msg": "Old password is wrong!"
                    }
                    return jsonify(retJson)


        # --------------------------------

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal User Address Update
class NormalUserAddressUpdate(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************

            # get the data
            postedData = request.get_json()

            # Get the data
            email = postedData["email"]
            address = postedData["address"]

            per_address = postedData["per_address"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            myquery = {"email": email}
            newvalues = {"$set": {
                "address": address,

                "per_address": per_address,

                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            normalusercol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Address updated"
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal User Profile Info Update
class NormalUserProfileInfoUpdate(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************

            # get the data
            postedData = request.get_json()

            # Get the data
            email = postedData["email"]
            fname = postedData["fname"]
            lname = postedData["lname"]
            mobile = postedData["mobile"]
            date_of_birth = postedData["date_of_birth"]
            place_of_birth = postedData["place_of_birth"]
            gender = postedData["gender"]
            marital_status = postedData["marital_status"]
            nationality = postedData["nationality"]
            nid = postedData["nid"]
            religion = postedData["religion"]
            designation = postedData["designation"]

            date_of_joining = postedData["date_of_joining"]
            employee_id = postedData["employee_id"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            myquery = {"email": email}
            newvalues = {"$set": {
                "username": fname,
                "fname": fname,
                "lname": lname,
                "mobile": mobile,
                "date_of_birth": date_of_birth,
                "place_of_birth": place_of_birth,
                "marital_status": marital_status,
                "nationality": nationality,
                "nid": nid,
                "gender": gender,
                "religion": religion,
                "designation": designation,

                "date_of_joining": date_of_joining,
                "employee_id": employee_id,

                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            normalusercol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Profile info updated"
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal User avatar image upload
class NormalUserAvatarImageUpload(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            email = request.form['email']

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    "status": "failed",
                    "msg": "User not found with this email"
                }

                return jsonify(retJson)

                # work to do
            if request.method == 'POST':
                if 'avatar_img' in request.files:
                    file_attachment = request.files['avatar_img']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                    # return data['link']
                    # return (str(j1))
                myquery = {"email": email}
                newvalues = {"$set": {
                    "avatar_img": attachmentPath,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                normalusercol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Avatar image updated",
                    "path": attachmentPath
                }
                return jsonify(retJson)



        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal User cover image upload
class NormalUserCoverImageUpload(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            email = request.form['email']

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    "status": "failed",
                    "msg": "User not found with this email"
                }

                return jsonify(retJson)

                # work to do
            if request.method == 'POST':
                if 'cover_img' in request.files:
                    file_attachment = request.files['cover_img']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                    # return data['link']
                    # return (str(j1))
                myquery = {"email": email}
                newvalues = {"$set": {
                    "cover_img": attachmentPath,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                normalusercol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Cover image updated",
                    "path": attachmentPath
                }
                return jsonify(retJson)



        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Normal User profile info
class GetNormalUserProfileInfo(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            # get the data
            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            result = normalusercol.find({"email": email})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["username"] = str(i["username"])
                user_data["email"] = str(i["email"])
                user_data["avatar_img"] = str(i["avatar_img"])
                user_data["cover_img"] = str(i["cover_img"])
                user_data["created_at"] = str(i["created_at"])
                user_data["fname"] = str(i["fname"])
                user_data["lname"] = str(i["lname"])
                user_data["mobile"] = str(i["mobile"])
                user_data["marital_status"] = str(i["marital_status"])
                user_data["date_of_birth"] = str(i["date_of_birth"])
                user_data["place_of_birth"] = str(i["place_of_birth"])
                user_data["gender"] = str(i["gender"])
                user_data["religion"] = str(i["religion"])
                user_data["nationality"] = str(i["nationality"])
                user_data["nid"] = str(i["nid"])
                user_data["designation"] = str(i["designation"])
                user_data["role"] = str(i["role"])

                user_data["date_of_joining"] = str(i["date_of_joining"])
                user_data["employee_id"] = str(i["employee_id"])

                # holder.append(user_data)

            retJson = {
                "status": "ok",
                "msg": user_data
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Normal User address
class GetNormalUserAddress(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            # get the data
            postedData = request.get_json()

            # Get the data a
            email = postedData["email"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            result = normalusercol.find({"email": email})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["user_id"] = str(i["_id"])
                user_data["address"] = str(i["address"])

                user_data["per_address"] = str(i["per_address"])

            retJson = {
                "status": "ok",
                "msg": user_data
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


class NormalUserPasswordResetRequestByEmail(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]

        # Check user with email
        if not UserExistNormal(email):
            retJson = {
                "status": "failed",
                "msg": "Email not exists"
            }

            return jsonify(retJson)

        iat = datetime.utcnow()
        exp = iat + timedelta(days=30)
        nbf = iat
        payload = {
            'exp': exp,
            'iat': iat,
            'nbf': nbf,
            # 'aud': str(email)
        }
        if email:
            payload['sub'] = email

        tempData = jwt.encode(
            payload,
            str(secret_key),
            algorithm='HS256'
        ).decode('utf-8')

        data_to_insert = {"email": email, "token": tempData}

        isTokenInserted = tokenbank.insert_one(data_to_insert)

        url = "http://tuembd.com/test_mail.php?email=" + email + "&token=" + tempData

        payload = {
            'email': email,
            'token': tempData
        }
        headers = {
            'Content-Type': 'application/json'
        }

        # response = requests.request("POST", url, headers=headers, data=payload)

        response = requests.post(
            url,
            headers=headers,
            data={
                'email': email,
                'token': tempData
            }
        )
        # data = json.loads(response.text)['data']

        # print(response.text.encode('utf8'))
        retJosn = {
            "status": "ok",
            "msg": tempData,
            "email_status": str(response.text)
            # "tokenStatus": str(isTokenInserted)
        }

        return jsonify(retJosn)


class NormalUserPasswordResetReedemByEmail(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        token = postedData["token"]
        password = postedData["password"]
        password_confirmation = postedData["password_confirmation"]

        payload = jwt.decode(token, str(secret_key), algorithms='HS256')
        # return payload['sub']
        which_user = payload['sub']

        # Check user with email
        if not TokenExist(token):
            retJson = {
                "status": "failed",
                "msg": "Password reset token is not valid"
            }

            return jsonify(retJson)

        # Check user with email
        if not UserExistNormal(email):
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        if password != password_confirmation:
            retJson = {
                "status": "failed",
                "msg": "Password & confirm password doesn't matched!"
            }

            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        myquery = {"email": email}
        newvalues = {"$set": {
            "password": hashed_pw,
            "updated_at": datetime.today().strftime('%d-%m-%Y')
        }}

        normalusercol.update_one(myquery, newvalues)

        deleteToken = {"token": token}

        isTokenDeleted = tokenbank.delete_one(deleteToken)

        retJson = {
            "status": "ok",
            "msg": "Password reset success"
            # "token_status": str(isTokenDeleted)
        }
        return jsonify(retJson)


# -- Normal User Status update
class NormalUserStatusUpdate(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************

            # get the data
            postedData = request.get_json()

            # Get the data
            email = postedData["email"]
            status = postedData["status"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this email'
                }
                return jsonify(retJson)

            myquery = {"email": email}
            newvalues = {"$set": {
                "status": status,

                "updated_at": datetime.today().strftime('%d-%m-%Y')
            }}

            normalusercol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "User status updated"
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Normal User status
class GetNormalUserStatus(Resource):
    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            payload = jwt.decode(parts[1], str(secret_key), algorithms='HS256')
            # return payload['sub']
            which_user = payload['sub']

            # get the data
            postedData = request.get_json()

            # Get the data
            email = postedData["email"]

            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this email'
                }
                return jsonify(retJson)

            result = normalusercol.find({"email": email})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["status"] = str(i["status"])
                # holder.append(user_data)

            retJson = {
                "status": "ok",
                "msg": user_data
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Normal User Status field add
class NormalUserStatusFieldAdd(Resource):
    def get(self):
        try:
            # *******************************************
            # *******************************************

            data = normalusercol.find()

            for i in data:
                myquery = {"email": str(i["email"])}
                newvalues = {"$set": {
                    "status": 1,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')
                }}

                normalusercol.update_one(myquery, newvalues)

            data2 = normalusercol.find()
            holder2 = []
            for i in data2:
                holder2.append(i)

            retJson = {
                "status": "ok",
                "msg": str(holder2)
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Task was failed"
            }

            return jsonify(retJson)


# -- Get All Institute IDs
class GetAllInstituteIDs(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = institutecol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "active": str(i["active"]),
                    "institute_id": str(i["institute_id"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "current_page": 1,
                    "data": holder
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


def BillingInvoiceMonthCheck(id, month, year):
    if billcol.find({"institute_id": id, "month": month, "year": year}).count() == 0:
        return False
    else:
        return True


# -- Create new invoice
class CreateNewInvoice(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            institute_id = postedData["institute_id"]
            institute_name = postedData["institute_name"]
            month = postedData["month"]
            year = postedData["year"]
            amount = postedData["amount"]
            generated_by = postedData["generated_by"]

            if BillingInvoiceMonthCheck(institute_id, month, year):
                retJson = {
                    "status": "failed",
                    "msg": "Bill already generated in this month"
                }

                return jsonify(retJson)

            """if BillingInvoiceYearCheck(institute_id, year):
                retJson = {
                    "status": "failed",
                    "msg": "Bill already generated in this month"
                }

                return jsonify(retJson)"""

            #
            sts = billcol.insert_one({
                "institute_id": institute_id,
                "institute_name": institute_name,
                "month": month,
                "year": year,
                "amount": amount,
                "file_path": "",
                "status": "Pending",
                "generated_by": generated_by,
                "created_at": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }).inserted_id

            retJson = {
                "status": "ok",
                "msg": str(sts)
            }

            return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get All Invoice list
class GetAllInvoiceList(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = billcol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "institute_id": str(i["institute_id"]),
                    "institute_name": str(i["institute_name"]),
                    "month": str(i["month"]),
                    "year": str(i["year"]),
                    "amount": str(i["amount"]),
                    "file_path": str(i["file_path"]),
                    "status": str(i["status"]),
                    "generated_by": str(i["generated_by"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "current_page": 1,
                    "data": holder
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Invoice API for dashbord
class InvoiceAPIForDashboard(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = billcol.find({})

            total = 0
            pending = 0
            approved = 0

            holder = []
            for i in result:
                total = total + 1

                status = str(i["status"])

                if status == "Approved":
                    approved = approved + 1
                else:
                    pending = pending + 1

            retJson = {
                "status": "ok",
                "data": {
                    "total": total,
                    "approved": approved,
                    "pending": pending
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


def InvoiceExistWithId(id):
    if billcol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


# -- View Single Invoice
class ViewSingleInvoice(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            # Get the data
            id = postedData["id"]

            # Check id is valid or not
            if ObjectId.is_valid(id):

                # Check id is exist
                if not InvoiceExistWithId(ObjectId(id)):
                    retJson = {
                        "status": "failed",
                        "msg": "Invoice with this id not found"
                    }

                    return jsonify(retJson)

                result = billcol.find({"_id": ObjectId(id)})

                invoice_data = {}
                for i in result:
                    invoice_data["id"] = str(i["_id"])
                    invoice_data["institute_id"] = str(i["institute_id"])
                    invoice_data["institute_name"] = str(i["institute_name"])
                    invoice_data["month"] = str(i["month"])
                    invoice_data["year"] = str(i["year"])
                    invoice_data["amount"] = str(i["amount"])
                    invoice_data["file_path"] = str(i["file_path"])
                    invoice_data["status"] = str(i["status"])
                    invoice_data["generated_by"] = str(i["generated_by"])
                    invoice_data["created_at"] = str(i["created_at"])
                    invoice_data["updated_at"] = str(i["updated_at"])

                retJson = {
                    "status": "ok",
                    "msg": invoice_data
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid invoice id"
                }

                return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete all invoice data
class DeleteInvoiceCollection(Resource):
    def get(self):
        billcol.drop()

        retJson = {
            "status": "ok",
            "msg": "All collection data deleted successfully!"
        }

        return jsonify(retJson)


# -- Update invoice
class UpdateInvoice(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            institute_id = postedData["institute_id"]
            institute_name = postedData["institute_name"]
            month = postedData["month"]
            year = postedData["year"]
            amount = postedData["amount"]
            generated_by = postedData["generated_by"]

            # Check id is exist
            if not InvoiceExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invoice with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "institute_id": institute_id,
                "institute_name": institute_name,
                "month": month,
                "year": year,
                "amount": amount,
                "generated_by": generated_by,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = billcol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Invoice updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update invoice approval
class UpdateInvoiceApprovalStatus(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            status = postedData["status"]

            # Check id is exist
            if not InvoiceExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Invoice with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "status": status
                # "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = billcol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Invoice approved successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Attach payment receipt with invoice
class AttachPaymentReceiptWithInvoiceSpecial(Resource):
    def post(self):

        try:
            invoice_id = request.form['invoice_id']

            if request.method == 'POST':

                attachmentPath = ""

                ############################ Attachment upload

                if 'file_attachment' in request.files:
                    file_attachment = request.files['file_attachment']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                ############################ end of attachement upload

                myquery = {"_id": ObjectId(invoice_id)}
                newvalues = {"$set": {
                    "file_path": attachmentPath,
                    "status": "Pending",
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                }}

                sts = billcol.update_one(myquery, newvalues)

                retJson = {
                    "status": "ok",
                    "msg": "Attachment uploaded successfully",
                    "data": {
                        "status": "Pending",
                        "file_url": attachmentPath

                    }

                }

                return jsonify(retJson)
            else:
                retJson = {
                    "status": "failed",
                    "msg": "Data fields mismatched"
                }

                return jsonify(retJson)




        except:
            retJson = {
                "status": "failed",
                "msg": "No data found"
            }

            return jsonify(retJson)


def GetInstituteContact(id):
    try:
        contact = institutecol.find({
            "institute_id": id
        })[0]["phone"]
        return contact
    except:
        return "NA"


def GetInstituteEmail(id):
    try:
        email = institutecol.find({
            "institute_id": id
        })[0]["email"]
        return email
    except:
        return "NA"


# -- Get All Institute list with Invoice
class GetAllInstituteListWithInvoice(Resource):
    def get(self):

        try:
            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = billcol.find({})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "institute_id": str(i["institute_id"]),
                    "institute_name": str(i["institute_name"]),
                    "month": str(i["month"]),
                    "year": str(i["year"]),
                    "amount": str(i["amount"]),
                    "file_path": str(i["file_path"]),
                    "status": str(i["status"]),
                    "phone": GetInstituteContact(str(i["institute_id"])),
                    "email": GetInstituteEmail(str(i["institute_id"])),
                    "generated_by": str(i["generated_by"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "current_page": 1,
                    "data": holder
                }
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


def InstituteExistStringId(id):
    if institutecol.find({"institute_id": id}).count() == 0:
        return False
    else:
        return True


def InstituteExistWithIntegerID(id):
    if institutecol.find({"integer_id": id}).count() == 0:
        return False
    else:
        return True


# -- Get all invoice of an institute
class GetAllInvoicesSingleInstitute(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            institute_id_string = postedData["institute_id_string"]

            # Check id is exist
            if not InstituteExistStringId(institute_id_string):
                retJson = {
                    "status": "failed",
                    "msg": "Institute not found"
                }

                return jsonify(retJson)

            result = institutecol.find({"institute_id": institute_id_string})
            package_id_db = ""
            package_data = {}

            for i in result:
                package_data["id"] = str(i["_id"])
                package_data["institute_id"] = str(i["institute_id"])
                package_data["name"] = str(i["name"])
                package_data["address"] = str(i["address"])
                package_data["email"] = str(i["email"])
                package_data["phone"] = str(i["phone"])
                package_data["created_at"] = str(i["created_at"])
                package_data["updated_at"] = str(i["updated_at"])
                package_data["integer_id"] = str(i["integer_id"])

            result2 = billcol.find({"institute_id": institute_id_string})

            holder = []
            for i in result2:
                data = {
                    "id": str(i["_id"]),
                    "institute_id": str(i["institute_id"]),
                    "institute_name": str(i["institute_name"]),
                    "month": str(i["month"]),
                    "year": str(i["year"]),
                    "amount": str(i["amount"]),
                    "file_path": str(i["file_path"]),
                    "status": str(i["status"]),
                    "generated_by": str(i["generated_by"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "details": package_data,
                    "data": holder
                }
            }

            return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get all invoice of an institute special
class GetAllInvoicesSingleInstituteSpecial(Resource):
    def post(self):

        try:
            postedData = request.get_json()

            # Get the data a
            id = postedData["id"]

            if not InstituteExistWithIntegerID(id):
                retJson = {
                    "status": "failed",
                    "msg": "No institute found with this id"
                }

                return jsonify(retJson)

            institute_id_string = institutecol.find({
                "integer_id": id
            })[0]["institute_id"]

            """retJson = {
                "int_id": id,
                "string_id": string_id
            }
            return jsonify(retJson)"""

            result = institutecol.find({"institute_id": institute_id_string})
            package_id_db = ""
            package_data = {}

            for i in result:
                package_data["id"] = str(i["integer_id"])
                package_data["institute_id"] = str(i["institute_id"])
                package_data["name"] = str(i["name"])
                package_data["address"] = str(i["address"])
                package_data["email"] = str(i["email"])
                package_data["phone"] = str(i["phone"])
                package_data["created_at"] = str(i["created_at"])
                package_data["updated_at"] = str(i["updated_at"])
                package_data["string_id"] = str(i["_id"])

            result2 = billcol.find({"institute_id": institute_id_string})

            holder = []
            for i in result2:
                data = {
                    "id": str(i["_id"]),
                    "institute_id": str(i["institute_id"]),
                    "institute_name": str(i["institute_name"]),
                    "month": str(i["month"]),
                    "year": str(i["year"]),
                    "amount": str(i["amount"]),
                    "file_path": str(i["file_path"]),
                    "status": str(i["status"]),
                    "generated_by": str(i["generated_by"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "msg": {
                    "details": package_data,
                    "data": holder
                }
            }

            return jsonify(retJson)





        except:
            retJson = {
                "status": "failed",
                "msg": "Not found any data in server"
            }
            return jsonify(retJson)


# -- Test other class api
class TestOtherClass(Resource):
    def get(self):
        retJson = {
            "status": "ok",
            "msg": {
                "details": geloc.getUpazilla(2)

            }
        }

        return jsonify(retJson)


# -- Get all divisions
class GetAllDivisions(Resource):
    def get(self):
        retJson = {
            "status": "ok",
            "data": geloc.getDivisions()
        }

        return jsonify(retJson)


# -- Get all districts by division id
class GetDistricts(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        division_id = postedData["division_id"]

        retJson = {
            "status": "ok",
            "data": geloc.getDistrict(division_id)
        }

        return jsonify(retJson)


# -- Get all upazillas by district id
class GetUpazillas(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        district_id = postedData["district_id"]

        retJson = {
            "status": "ok",
            "data": geloc.getUpazilla(district_id)
        }

        return jsonify(retJson)


# -- User common login
class UserCommonLogin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        password = postedData["password"]

        # Check user with email
        if not UserExist(email):
            """retJson = {
                'status': 301,
                'msg': 'No user exist with this username'
            }
            return jsonify(retJson)"""

            ## check another db
            # Check user with email
            if not UserExistNormal(email):
                retJson = {
                    'status': 301,
                    'msg': 'No user exist with this username'
                }
                return jsonify(retJson)

            # Check password
            if not verifyPwNormal(email, password):
                retJson = {
                    'status': 301,
                    'msg': 'Wrong username or password'
                }
                return jsonify(retJson)

            userid = normalusercol.find({
                "email": email
            })[0]["_id"]

            role = normalusercol.find({
                "email": email
            })[0]["role"]

            date_of_joining = normalusercol.find({
                "email": email
            })[0]["date_of_joining"]

            employee_id = normalusercol.find({
                "email": email
            })[0]["employee_id"]

            # ------
            result = usertypecol.find({'typename': role})

            package_data = {}
            for i in result:
                package_data["type_id"] = str(i["_id"])
                package_data["typename"] = str(i["typename"])
                package_data["active"] = str(i["active"])
                package_data["user"] = str(i["user"])
                package_data["institute"] = str(i["institute"])
                package_data["package"] = str(i["package"])
                package_data["bill"] = str(i["bill"])
                package_data["payment"] = str(i["payment"])
                package_data["created_at"] = str(i["created_at"])
                package_data["updated_at"] = str(i["updated_at"])

            # ----------------------

            # -- Generate an access token
            retJson = {
                'status': 200,
                'msg': {
                    "id": str(userid),
                    "token": generateAuthToken(email),
                    "date_of_joining": str(date_of_joining),
                    "employee_id": str(employee_id),
                    "role": str(role),
                    "role_details": package_data
                }
            }
            return jsonify(retJson)

            #############################

        # Check password
        if not verifyPw(email, password):
            retJson = {
                'status': 301,
                'msg': 'Wrong username or password'
            }
            return jsonify(retJson)

        userid = superad.find({
            "email": email
        })[0]["_id"]

        role = superad.find({
            "email": email
        })[0]["role"]

        date_of_joining = superad.find({
            "email": email
        })[0]["date_of_joining"]

        employee_id = superad.find({
            "email": email
        })[0]["employee_id"]

        # -- Generate an access token
        retJson = {
            'status': "ok",
            'msg': {
                "id": str(userid),
                "token": generateAuthToken(email),
                "date_of_joining": str(date_of_joining),
                "employee_id": str(employee_id),
                "role": str(role)
            }
        }
        return jsonify(retJson)


# -- Delete all normal user
class DeleteAllNormalUser(Resource):
    def get(self):
        normalusercol.drop()

        retJson = {
            "status": "ok",
            "msg": "All normal user data deleted successfully!"
        }

        return jsonify(retJson)


# -- Save new Email
class SendNewEmail(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            to_address = request.form['to_address']
            from_address = request.form['from_address']

            title = request.form['title']
            body = request.form['body']
            status = request.form['status']

            """# Check user is exists with to_address
            if not UserExist(to_address) and not UserExistNormal(to_address):
                retJson = {
                    "status": "failed",
                    "msg": "Receiver's email not found in the system"
                }

                return jsonify(retJson)

            # Check s user is exists with from_address
            if not UserExist(from_address) and not UserExistNormal(from_address):
                retJson = {
                    "status": "failed",
                    "msg": "Sender's email not found in the system"
                }

                return jsonify(retJson)"""

            if request.method == 'POST':

                attachmentPath = ""
                imagePath = ""

                ############################ Attachment upload

                if 'file_attachment' in request.files:
                    file_attachment = request.files['file_attachment']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                ############################ end of attachement upload

                ############################ Image upload

                if 'image_attachment' in request.files:

                    image_attachment = request.files['image_attachment']
                    filename = str(time.time_ns()) + "_" + image_attachment.filename
                    image_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    imagePath = data
                else:
                    imagePath = ""

                ############################ end of attachement upload

            sts = emailcol.insert_one({
                "to_address": to_address,
                "from_address": from_address,
                "title": title,
                "body": body,
                "status": status,
                "deleted_by_sender": 0,
                "deleted_by_receiver": 0,
                "file_attachement": str(attachmentPath),
                "image_attachement": str(imagePath),
                "sending_date": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }).inserted_id

            if status == "draft":
                retJson = {
                    "status": "ok",
                    "msg": "Email saved as draft successfully"

                }
            else:
                retJson = {
                    "status": "ok",
                    "msg": "Email sent successfully"

                }

                url = "http://tuembd.com/test_mail_2.php?email=" + to_address + "&subject=" + title + "&body=" + body + "&sender=" + from_address

                headers = {
                    'Content-Type': 'application/json'
                }

                # response = requests.request("POST", url, headers=headers, data=payload)

                response = requests.post(
                    url,
                    headers=headers

                )

            return jsonify(retJson)




        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Save new Multiple Email
class SendNewEmailMulitple(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            to_address = request.form['to_address']
            from_address = request.form['from_address']

            title = request.form['title']
            body = request.form['body']
            status = request.form['status']

            attachmentPath = ""
            imagePath = ""
            if request.method == 'POST':

                ############################ Attachment upload

                if 'file_attachment' in request.files:
                    file_attachment = request.files['file_attachment']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                ############################ end of attachement upload

                ############################ Image upload

                if 'image_attachment' in request.files:

                    image_attachment = request.files['image_attachment']
                    filename = str(time.time_ns()) + "_" + image_attachment.filename
                    image_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    imagePath = data
                else:
                    imagePath = ""

                ############################ end of attachement upload

            x = to_address.split(",")

            for i in x:
                """# Check s user is exists with from_address
                if not UserExist(from_address) and not UserExistNormal(from_address):
                    retJson = {
                        "status": "failed",
                        "msg": "Sender's email not found in the system"
                    }

                    return jsonify(retJson)"""

                sts = emailcol.insert_one({
                    "to_address": i,
                    "from_address": from_address,
                    "title": title,
                    "body": body,
                    "status": status,
                    "deleted_by_sender": 0,
                    "deleted_by_receiver": 0,
                    "file_attachement": str(attachmentPath),
                    "image_attachement": str(imagePath),
                    "sending_date": datetime.today().strftime('%d-%m-%Y'),
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                }).inserted_id

                url = "http://tuembd.com/test_mail_2.php?email=" + to_address + "&subject=" + title + "&body=" + body + "&sender=" + from_address

                headers = {
                    'Content-Type': 'application/json'
                }

                # response = requests.request("POST", url, headers=headers, data=payload)

                response = requests.post(
                    url,
                    headers=headers

                )

            retJson = {
                "status": "ok",
                "msg": "Email sent successfully to all provided emails"
            }

            return jsonify(retJson)








        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Delete all email data
class DeleteAllEmailData(Resource):
    def get(self):
        emailcol.drop()

        retJson = {
            "status": "ok",
            "msg": "All email data deleted successfully!"
        }

        return jsonify(retJson)


# -- Get Email for user inbox
class GetEmailForInbox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email = postedData["email"]

            result = emailcol.find({"to_address": email, "deleted_by_receiver": 0})

            holder = []
            count = 0
            for i in result:
                data = {
                    "email_id": str(i["_id"]),
                    "title": str(i["title"]),
                    "sender": str(i["from_address"]),
                    "sending_date": str(i["sending_date"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Email full details
class GetEmailFullDetails(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email_id = postedData["email_id"]

            # Check id is valid or not
            if ObjectId.is_valid(email_id):

                result = emailcol.find({"_id": ObjectId(email_id)})

                holder = []

                count = 0
                for i in result:
                    data = {
                        "email_id": str(i["_id"]),
                        "to_address": str(i["to_address"]),
                        "from_address": str(i["from_address"]),
                        "title": str(i["title"]),
                        "body": str(i["body"]),
                        "status": str(i["status"]),
                        "file_attachement": str(i["file_attachement"]),
                        "image_attachement": str(i["image_attachement"]),
                        "deleted_by_sender": str(i["deleted_by_sender"]),
                        "deleted_by_receiver": str(i["deleted_by_receiver"]),
                        "sending_date": str(i["sending_date"]),
                        "updated_at": str(i["updated_at"])

                    }
                    count = count + 1

                    holder.append(data)

                retJson = {
                    "status": "ok",
                    "data": holder
                }

                return jsonify(retJson)


            else:
                retJson = {
                    "status": "failed",
                    "msg": "Invalid email id"
                }

                return jsonify(retJson)






        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Email for user sent box
class GetEmailForSentBox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email = postedData["email"]

            result = emailcol.find({"from_address": email, "deleted_by_sender": 0})

            holder = []
            count = 0
            for i in result:
                data = {
                    "email_id": str(i["_id"]),
                    "title": str(i["title"]),
                    "receiver": str(i["to_address"]),
                    "sending_date": str(i["sending_date"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)


        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get Email for user draft box
class GetEmailForDraftBox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email = postedData["email"]

            result = emailcol.find({"from_address": email, "status": "draft"})

            holder = []
            count = 0
            for i in result:
                data = {
                    "email_id": str(i["_id"]),
                    "title": str(i["title"]),
                    "receiver": str(i["to_address"]),
                    "sending_date": str(i["sending_date"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


def EmailExistsWithID(id):
    if emailcol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


# -- Save  Email as draft
class SaveEmailAsDraft(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            to_address = request.form['to_address']
            from_address = request.form['from_address']

            title = request.form['title']
            body = request.form['body']
            status = request.form['status']

            if request.method == 'POST':

                attachmentPath = ""
                imagePath = ""

                ############################ Attachment upload

                if 'file_attachment' in request.files:
                    file_attachment = request.files['file_attachment']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                ############################ end of attachement upload

                ############################ Image upload

                if 'image_attachment' in request.files:

                    image_attachment = request.files['image_attachment']
                    filename = str(time.time_ns()) + "_" + image_attachment.filename
                    image_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    imagePath = data
                else:
                    imagePath = ""

                ############################ end of attachement upload

            sts = emailcol.insert_one({
                "to_address": to_address,
                "from_address": from_address,
                "title": title,
                "body": body,
                "status": status,
                "deleted_by_sender": 0,
                "deleted_by_receiver": 0,
                "file_attachement": str(attachmentPath),
                "image_attachement": str(imagePath),
                "sending_date": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }).inserted_id

            if status == "draft":
                retJson = {
                    "status": "ok",
                    "msg": "Email saved as draft successfully"

                }
            else:
                retJson = {
                    "status": "ok",
                    "msg": "Email sent successfully"

                }

            return jsonify(retJson)




        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Send email from DraftBox
class SendEmailFromDraftBox(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            email_id = request.form['email_id']
            to_address = request.form['to_address']
            from_address = request.form['from_address']

            title = request.form['title']
            body = request.form['body']
            status = request.form['status']

            # Check user is exists with to_address
            if not UserExist(to_address) and not UserExistNormal(to_address):
                retJson = {
                    "status": "failed",
                    "msg": "Receiver's email not found in the system"
                }

                return jsonify(retJson)

            # Check s user is exists with from_address
            if not UserExist(from_address) and not UserExistNormal(from_address):
                retJson = {
                    "status": "failed",
                    "msg": "Sender's email not found in the system"
                }

                return jsonify(retJson)

            # Check id is exist
            if not EmailExistsWithID(ObjectId(email_id)):
                retJson = {
                    "status": "failed",
                    "msg": "Email with this id not found"
                }

                return jsonify(retJson)

            if request.method == 'POST':

                attachmentPath = ""
                imagePath = ""

                ############################ Attachment upload
                if 'file_attachment' in request.files:
                    file_attachment = request.files['file_attachment']
                    filename = str(time.time_ns()) + "_" + file_attachment.filename
                    file_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    attachmentPath = data
                else:
                    attachmentPath = ""

                ############################ end of attachement upload

                ############################ Image upload

                if 'image_attachment' in request.files:

                    image_attachment = request.files['image_attachment']
                    filename = str(time.time_ns()) + "_" + image_attachment.filename
                    image_attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    filepath = str(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                    url = file_upload_server_path_php

                    payload = {'main_url': file_upload_server_path}
                    files = [
                        ('fileToUpload', open(filepath, 'rb'))
                    ]
                    headers = {}

                    response = requests.request("POST", url, headers=headers, data=payload, files=files)
                    # return response.text
                    data = json.loads(response.text)['message']
                    imagePath = data
                else:
                    imagePath = ""

                ############################ end of attachement upload

            myquery = {"_id": ObjectId(email_id)}
            newvalues = {"$set": {
                "to_address": to_address,
                "from_address": from_address,
                "title": title,
                "body": body,
                "status": status,
                "deleted_by_sender": 0,
                "deleted_by_receiver": 0,
                "file_attachement": str(attachmentPath),
                "image_attachement": str(imagePath),
                "sending_date": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = emailcol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Email sent successfully"
            }

            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Trash email by sender
class TrashEmailBySender(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            email_id = request.form['email_id']
            from_address = request.form['from_address']

            # Check s user is exists with from_address
            if not UserExist(from_address) and not UserExistNormal(from_address):
                retJson = {
                    "status": "failed",
                    "msg": "Sender's email not found in the system"
                }

                return jsonify(retJson)

            # Check id is exist
            if not EmailExistsWithID(ObjectId(email_id)):
                retJson = {
                    "status": "failed",
                    "msg": "Email with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(email_id), "from_address": from_address}
            newvalues = {"$set": {

                "deleted_by_sender": 1,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = emailcol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Email moved to trashbox by sender successfully"
            }

            return jsonify(retJson)




        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Trash email by receiver
class TrashEmailByReceiver(Resource):

    def post(self):
        auth_header_value = request.headers.get('Authorization', None)

        if not auth_header_value:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        parts = auth_header_value.split()

        if parts[0].lower() != 'bearer':
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) == 1:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)
        elif len(parts) > 2:
            # return False
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        try:
            # *******************************************
            # *******************************************
            email_id = request.form['email_id']
            to_address = request.form['to_address']

            # Check s user is exists with from_address
            if not UserExist(to_address) and not UserExistNormal(to_address):
                retJson = {
                    "status": "failed",
                    "msg": "Receiver's email not found in the system"
                }

                return jsonify(retJson)

            # Check id is exist
            if not EmailExistsWithID(ObjectId(email_id)):
                retJson = {
                    "status": "failed",
                    "msg": "Email with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(email_id), "to_address": to_address}
            newvalues = {"$set": {

                "deleted_by_receiver": 1,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = emailcol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Email moved to trashbox by receiver successfully"
            }

            return jsonify(retJson)




        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }

            return jsonify(retJson)


# -- Get Email for user trash box
class GetEmailForTrashBox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email = postedData["email"]

            result = emailcol.find({"from_address": email, "deleted_by_sender": 1})

            holder = []
            count = 0
            for i in result:
                data = {
                    "email_id": str(i["_id"]),
                    "title": str(i["title"]),
                    "receiver": str(i["to_address"]),
                    "sending_date": str(i["sending_date"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            result2 = emailcol.find({"to_address": email, "deleted_by_receiver": 1})

            for i in result2:
                data2 = {
                    "email_id": str(i["_id"]),
                    "title": str(i["title"]),
                    "receiver": str(i["to_address"]),
                    "sending_date": str(i["sending_date"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data2)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Get total Email counter
class GetTotalEmailsCounter(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            email = postedData["email"]

            inbox_total = 0
            sentbox_total = 0
            draftbox_total = 0
            trashbox_total = 0

            # all emails in inbox
            inbox_total = emailcol.find({"to_address": email, "deleted_by_receiver": 0}).count()

            # all emails in sentbox
            sentbox_total = emailcol.find({"from_address": email, "deleted_by_sender": 0}).count()

            # all emails in draftbox
            draftbox_total = emailcol.find({"from_address": email, "status": "draft"}).count()

            # all emails in trashbox
            trashbox_total = emailcol.find({"from_address": email, "deleted_by_sender": 1}).count()
            trashbox_total = trashbox_total + emailcol.find({"to_address": email, "deleted_by_receiver": 1}).count()

            retJson = {
                "status": "ok",
                "data": {
                    "inbox": inbox_total,
                    "sentbox": sentbox_total,
                    "draft": draftbox_total,
                    "deleted": trashbox_total
                }
            }

            return jsonify(retJson)

        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete Email from Inbox
class DeleteEmailFromInbox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            receiver = postedData["receiver"]
            parameters = postedData["parameters"]

            # finding the dynamic paramerters values
            countT = len(parameters)

            params = []
            for i in range(countT):
                id = parameters[i]['id']

                # ----------------
                myquery = {"_id": ObjectId(id), "to_address": receiver}
                newvalues = {"$set": {

                    "deleted_by_receiver": 1,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                }}

                emailcol.update_one(myquery, newvalues)

                # ----------------------------

            retJson = {
                "status": "ok",
                "msg": "All emails moved to trashbox"
            }

            return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete Email from SentBox
class DeleteEmailFromSentBox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            sender = postedData["sender"]
            parameters = postedData["parameters"]

            # finding the dynamic paramerters values
            countT = len(parameters)

            params = []
            for i in range(countT):
                id = parameters[i]['id']

                # ----------------
                myquery = {"_id": ObjectId(id), "from_address": sender}
                newvalues = {"$set": {

                    "deleted_by_sender": 1,
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                }}

                emailcol.update_one(myquery, newvalues)

                # ----------------------------

            retJson = {
                "status": "ok",
                "msg": "All emails moved to trashbox"
            }

            return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete Email from DraftBox
class DeleteEmailFromDraftBox(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            user = postedData["user"]
            parameters = postedData["parameters"]

            # finding the dynamic paramerters values
            countT = len(parameters)

            params = []
            for i in range(countT):
                id = parameters[i]['id']

                # ----------------
                myquery = {"_id": ObjectId(id), "from_address": user}
                newvalues = {"$set": {

                    "deleted_by_sender": 1,
                    "status": "deleted",
                    "updated_at": datetime.today().strftime('%d-%m-%Y')

                }}

                emailcol.update_one(myquery, newvalues)

                # ----------------------------

            retJson = {
                "status": "ok",
                "msg": "All emails moved to trashbox"
            }

            return jsonify(retJson)



        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


def SpecialSettingsPackageID():
    previous_id = settingspackagecol.count()
    present_id = previous_id + 1
    return present_id


def SettingsPackageExistWithName(name):
    if settingspackagecol.find({"package_item_name": name}).count() == 0:
        return False
    else:
        return True


def SettingsPackageExistWithId(id):
    if settingspackagecol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


# -- Settings package create
class SettingsPackageCreate(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            package_item_name = postedData["package_item_name"]
            package_number = postedData["package_number"]
            package_amount = postedData["package_amount"]

            # Check name is exist
            if SettingsPackageExistWithName(package_item_name):
                retJson = {
                    "status": "failed",
                    "msg": "Package is already exists with this name"
                }

                return jsonify(retJson)

            #
            sts = settingspackagecol.insert_one({
                "integer_id": SpecialSettingsPackageID(),
                "package_item_name": package_item_name,
                "package_number": package_number,
                "package_amount": package_amount,
                "active": 1,
                "created_at": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y'),

            }).inserted_id

            retJson = {
                "status": "ok",
                "msg": str(sts)
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete all settings package collection
class DeleteAllSettingsPackageCollection(Resource):
    def get(self):
        settingspackagecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All settings package data deleted successfully!"
        }

        return jsonify(retJson)


# -- Settings package list
class GetSettingsPackageList(Resource):
    def get(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = settingspackagecol.find({})

            holder = []
            count = 0
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "package_item_name": str(i["package_item_name"]),
                    "package_number": str(i["package_number"]),
                    "package_amount": str(i["package_amount"]),
                    "active": str(i["active"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Settings package with id
class GetSettingsPackageWithID(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            id = postedData["id"]

            result = settingspackagecol.find({"_id": ObjectId(id)})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "package_item_name": str(i["package_item_name"]),
                    "package_number": str(i["package_number"]),
                    "package_amount": str(i["package_amount"]),
                    "active": str(i["active"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update settings package active
class UpdateSettingsPackageActiveStatus(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            active = postedData["active"]

            # Check id is exist
            if not SettingsPackageExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Package with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = settingspackagecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Package status updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update settings package
class UpdateSettingsPackage(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            package_item_name = postedData["package_item_name"]
            package_number = postedData["package_number"]
            package_amount = postedData["package_amount"]
            active = postedData["active"]

            # Check id is exist
            if not SettingsPackageExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Package with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {

                "package_item_name": package_item_name,
                "package_number": package_number,
                "package_amount": package_amount,
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = settingspackagecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Settings package updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


def SpecialSettingsInstituteID():
    previous_id = settingsinstitutecol.count()
    present_id = previous_id + 1
    return present_id


def SettingsInstituteExistWithName(name):
    if settingsinstitutecol.find({"institute_name": name}).count() == 0:
        return False
    else:
        return True


def SettingsInstituteExistWithShortForm(short_form):
    if settingsinstitutecol.find({"short_form": short_form}).count() == 0:
        return False
    else:
        return True


def SettingsInstituteExistWithId(id):
    if settingsinstitutecol.find({"_id": id}).count() == 0:
        return False
    else:
        return True


# -- Settings institute create
class SettingsInstituteCreate(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            institute_name = postedData["institute_name"]
            short_form = postedData["short_form"]

            # Check name is exist
            if SettingsInstituteExistWithName(institute_name):
                retJson = {
                    "status": "failed",
                    "msg": "Institute is already exists with this name"
                }

                return jsonify(retJson)

            if SettingsInstituteExistWithShortForm(short_form):
                retJson = {
                    "status": "failed",
                    "msg": "Institute is already exists with this short form"
                }

                return jsonify(retJson)

            #
            sts = settingsinstitutecol.insert_one({
                "integer_id": SpecialSettingsInstituteID(),
                "institute_name": institute_name,
                "short_form": short_form,
                "active": 1,
                "created_at": datetime.today().strftime('%d-%m-%Y'),
                "updated_at": datetime.today().strftime('%d-%m-%Y'),

            }).inserted_id

            retJson = {
                "status": "ok",
                "msg": str(sts)
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete all settings institute collection
class DeleteAllSettingsInstituteCollection(Resource):
    def get(self):
        settingspackagecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All settings institute data deleted successfully!"
        }

        return jsonify(retJson)


# -- Settings institute list
class GetSettingsInstituteList(Resource):
    def get(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = settingsinstitutecol.find({})

            holder = []
            count = 0
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "institute_name": str(i["institute_name"]),
                    "short_form": str(i["short_form"]),
                    "active": str(i["active"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }
                count = count + 1

                holder.append(data)

            retJson = {
                "status": "ok",
                "count": count,
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Settings institute list special
class GetSettingsInstituteListSpecial(Resource):
    def get(self):
        result = settingsinstitutecol.find({})

        holder = []
        count = 0
        for i in result:
            data = {
                "id": str(i["_id"]),
                "institute_name": str(i["institute_name"]),
                "short_form": str(i["short_form"]),
                "active": str(i["active"]),
                "created_at": str(i["created_at"]),
                "updated_at": str(i["updated_at"])

            }
            count = count + 1

            holder.append(data)

        retJson = {
            "status": "ok",
            "count": count,
            "data": holder
        }

        return jsonify(retJson)


# -- Settings institute with id
class GetSettingsInstituteWithID(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()
            id = postedData["id"]

            result = settingsinstitutecol.find({"_id": ObjectId(id)})

            holder = []
            for i in result:
                data = {
                    "id": str(i["_id"]),
                    "institute_name": str(i["institute_name"]),
                    "short_form": str(i["short_form"]),
                    "active": str(i["active"]),
                    "created_at": str(i["created_at"]),
                    "updated_at": str(i["updated_at"])

                }

                holder.append(data)

            retJson = {
                "status": "ok",
                "data": holder
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update settings institute active
class UpdateSettingsInstituteActiveStatus(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            active = postedData["active"]

            # Check id is exist
            if not SettingsInstituteExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Institute with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = settingsinstitutecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Institute status updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Update settings institute
class UpdateSettingsInstitute(Resource):
    def post(self):

        try:

            auth_header_value = request.headers.get('Authorization', None)

            if not auth_header_value:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            parts = auth_header_value.split()

            if parts[0].lower() != 'bearer':
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) == 1:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)
            elif len(parts) > 2:
                # return False
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            postedData = request.get_json()

            # Get the data
            id = postedData["id"]
            institute_name = postedData["institute_name"]
            short_form = postedData["short_form"]
            active = postedData["active"]

            # Check id is exist
            if not SettingsInstituteExistWithId(ObjectId(id)):
                retJson = {
                    "status": "failed",
                    "msg": "Institute with this id not found"
                }

                return jsonify(retJson)

            myquery = {"_id": ObjectId(id)}
            newvalues = {"$set": {

                "institute_name": institute_name,
                "short_form": short_form,
                "active": active,
                "updated_at": datetime.today().strftime('%d-%m-%Y')

            }}

            sts = settingsinstitutecol.update_one(myquery, newvalues)

            retJson = {
                "status": "ok",
                "msg": "Settings institute updated successfully"
            }

            return jsonify(retJson)




        except jwt.ExpiredSignatureError:
            # return 'Signature expired' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)

        except jwt.InvalidTokenError:
            # return 'Invalid token' Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Invalid access token"
            }
            return jsonify(retJson)


# -- Delete all invoice
class DeleteAllInvoice(Resource):
    def get(self):
        billcol.drop()

        retJson = {
            "status": "ok",
            "msg": "All invoice data deleted successfully!"
        }

        return jsonify(retJson)


# -- Delete everything
class DeleteEverything(Resource):
    def get(self):
        superad.drop()
        tokenbank.drop()
        packagecol.drop()
        institutecol.drop()
        usertypecol.drop()
        normalusercol.drop()
        billcol.drop()
        emailcol.drop()
        settingspackagecol.drop()
        settingsinstitutecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All data of entire database cleared!"
        }

        return jsonify(retJson)


# -- Delete everything without super admin
class DeleteEverythingWithoutSuperAdmin(Resource):
    def get(self):
        # superad.drop()
        tokenbank.drop()
        packagecol.drop()
        institutecol.drop()
        usertypecol.drop()
        normalusercol.drop()
        billcol.drop()
        emailcol.drop()
        settingspackagecol.drop()
        settingsinstitutecol.drop()

        retJson = {
            "status": "ok",
            "msg": "All data of entire database cleared without super admin!"
        }

        return jsonify(retJson)


# -- Add super admin missing fields
class AddSuperAdminMissingFields(Resource):
    def get(self):
        try:
            # *******************************************
            # *******************************************

            data = superad.find()

            for i in data:
                myquery = {"_id": ObjectId(i["_id"])}
                newvalues = {"$set": {
                    "status": 1
                }}

                superad.update_one(myquery, newvalues)

            data2 = superad.find()
            holder2 = []
            for i in data2:
                holder2.append(i)

            retJson = {
                "status": "ok",
                "msg": str(holder2)
            }
            return jsonify(retJson)


        # ********************************************************************************************************
        # ********************************************************************************************************

        except jwt.ExpiredSignatureError:
            # return 'Signature expired. Please log in again.'
            retJson = {
                "status": "failed",
                "msg": "Task was failed"
            }

            return jsonify(retJson)


# -----------------------------------------------------------------------


api.add_resource(Welcome, '/welcome')
api.add_resource(RegisterSuperAdmin, '/register_super_admin')
api.add_resource(ShowAllSuperAdmin, '/show_all_super_admin')
api.add_resource(DeleteAllData, '/delete_all_data')

# Phase 1
api.add_resource(UserCommonLogin, '/authenticate')
api.add_resource(SuperAdminLogOut, '/logout')
api.add_resource(UpdateSuperAdminPassword, '/password-update')
api.add_resource(SuperAdminProfileInfoUpdate, '/info-update')
api.add_resource(GetSuperAdminProfileInfo, '/user-detail')
api.add_resource(SuperAdminAddressUpdate, '/update-user-address')
api.add_resource(GetSuperAdminAddress, '/user-address')
api.add_resource(SuperAdminAvatarImageUpload, '/avatar-update')
api.add_resource(SuperAdminCoverImageUpload, '/cover-img-update')
api.add_resource(SuperAdminPasswordResetRequestByEmail, '/password-reset-request')
api.add_resource(SuperAdminPasswordResetReedemByEmail, '/password-reset')

# Phase 3-4
api.add_resource(PackageSave, '/package-save')
api.add_resource(DeleteFullPackage, '/delete-full-package')
api.add_resource(GetPackageDetails, '/package-detail')
api.add_resource(GetAllPackageList, '/all-packages')
api.add_resource(PackageUpdate, '/package-update')
api.add_resource(PackageDelete, '/package-delete')
api.add_resource(PackageAddNewParameter, '/parameter-save')
api.add_resource(GetPackageParameterList, '/parameters')
api.add_resource(InstituteCreate, '/institute-create')
api.add_resource(DeleteFullInstituteCollection, '/delete-full-institute')
api.add_resource(InstituteUpdate, '/institute-update')
api.add_resource(GetInstituteDetails, '/institute-detail')
api.add_resource(GetAllInstituteList, '/institutes')
api.add_resource(InstituteActiveStatusChange, '/institute-status-update')
api.add_resource(InstituteDelete, '/institute-delete')

# special key for Phase 3-4
api.add_resource(GetAllPackageListSpecial, '/GetAllPackageListSpecial')
api.add_resource(GetPackageDetailsSpecial, '/GetPackageDetailsSpecial')
api.add_resource(GetPackageParameterListSpecial, '/GetPackageParameterListSpecial')
api.add_resource(GetInstituteDetailsSpecial, '/GetInstituteDetailsSpecial')
api.add_resource(GetAllInstituteListSpecial, '/GetAllInstituteListSpecial')

# Phase 2
api.add_resource(CreateUserType, '/CreateUserType')
api.add_resource(DeleteUserType, '/DeleteUserType')
api.add_resource(GetUserTypeList, '/GetUserTypeList')
api.add_resource(ViewSingleUserType, '/ViewSingleUserType')
api.add_resource(UpdateUserType, '/UpdateUserType')
api.add_resource(UpdateUserActivation, '/UpdateUserActivation')

api.add_resource(RegisterNewUserNormal, '/RegisterNewUserNormal')
api.add_resource(GetAllUserNormalList, '/GetAllUserNormalList')
api.add_resource(NormalUserLogin, '/NormalUserLogin')
api.add_resource(UpdateNormalUserPassword, '/UpdateNormalUserPassword')
api.add_resource(NormalUserAddressUpdate, '/NormalUserAddressUpdate')
api.add_resource(NormalUserProfileInfoUpdate, '/NormalUserProfileInfoUpdate')
api.add_resource(NormalUserAvatarImageUpload, '/NormalUserAvatarImageUpload')
api.add_resource(NormalUserCoverImageUpload, '/NormalUserCoverImageUpload')
api.add_resource(GetNormalUserProfileInfo, '/GetNormalUserProfileInfo')
api.add_resource(GetNormalUserAddress, '/GetNormalUserAddress')
api.add_resource(NormalUserPasswordResetRequestByEmail, '/NormalUserPasswordResetRequestByEmail')
api.add_resource(NormalUserPasswordResetReedemByEmail, '/NormalUserPasswordResetReedemByEmail')
api.add_resource(NormalUserStatusUpdate, '/NormalUserStatusUpdate')
api.add_resource(GetNormalUserStatus, '/GetNormalUserStatus')
api.add_resource(NormalUserStatusFieldAdd, '/NormalUserStatusFieldAdd')

api.add_resource(DeleteAllNormalUser, '/DeleteAllNormalUser')

# Phase 5
api.add_resource(GetAllInstituteIDs, '/GetAllInstituteIDs')
api.add_resource(CreateNewInvoice, '/CreateNewInvoice')
api.add_resource(GetAllInvoiceList, '/GetAllInvoiceList')
api.add_resource(ViewSingleInvoice, '/ViewSingleInvoice')
api.add_resource(DeleteInvoiceCollection, '/DeleteInvoiceCollection')
api.add_resource(UpdateInvoice, '/UpdateInvoice')
api.add_resource(UpdateInvoiceApprovalStatus, '/UpdateInvoiceApprovalStatus')
api.add_resource(GetAllInstituteListWithInvoice, '/GetAllInstituteListWithInvoice')
api.add_resource(GetAllInvoicesSingleInstitute, '/GetAllInvoicesSingleInstitute')
api.add_resource(GetAllInvoicesSingleInstituteSpecial, '/GetAllInvoicesSingleInstituteSpecial')
api.add_resource(AttachPaymentReceiptWithInvoiceSpecial, '/AttachPaymentReceiptWithInvoiceSpecial')

# -- From feedback Global
api.add_resource(GetAllDivisions, '/GetAllDivisions')
api.add_resource(GetDistricts, '/GetDistricts')
api.add_resource(GetUpazillas, '/GetUpazillas')

# -- Phase 6
api.add_resource(SendNewEmail, '/SendNewEmail')
api.add_resource(DeleteAllEmailData, '/DeleteAllEmailData')
api.add_resource(GetEmailForInbox, '/GetEmailForInbox')
api.add_resource(GetEmailFullDetails, '/GetEmailFullDetails')
api.add_resource(GetEmailForSentBox, '/GetEmailForSentBox')
api.add_resource(GetEmailForDraftBox, '/GetEmailForDraftBox')
api.add_resource(SaveEmailAsDraft, '/SaveEmailAsDraft')
api.add_resource(SendEmailFromDraftBox, '/SendEmailFromDraftBox')
api.add_resource(TrashEmailBySender, '/TrashEmailBySender')
api.add_resource(TrashEmailByReceiver, '/TrashEmailByReceiver')
api.add_resource(GetEmailForTrashBox, '/GetEmailForTrashBox')
api.add_resource(DeleteEmailFromInbox, '/DeleteEmailFromInbox')
api.add_resource(DeleteEmailFromSentBox, '/DeleteEmailFromSentBox')
api.add_resource(DeleteEmailFromDraftBox, '/DeleteEmailFromDraftBox')
api.add_resource(SendNewEmailMulitple, '/SendNewEmailMulitple')

api.add_resource(SettingsPackageCreate, '/SettingsPackageCreate')
api.add_resource(DeleteAllSettingsPackageCollection, '/DeleteAllSettingsPackageCollection')
api.add_resource(GetSettingsPackageList, '/GetSettingsPackageList')
api.add_resource(GetSettingsPackageWithID, '/GetSettingsPackageWithID')
api.add_resource(UpdateSettingsPackageActiveStatus, '/UpdateSettingsPackageActiveStatus')
api.add_resource(UpdateSettingsPackage, '/UpdateSettingsPackage')

api.add_resource(SettingsInstituteCreate, '/SettingsInstituteCreate')
api.add_resource(DeleteAllSettingsInstituteCollection, '/DeleteAllSettingsInstituteCollection')
api.add_resource(GetSettingsInstituteList, '/GetSettingsInstituteList')
api.add_resource(GetSettingsInstituteListSpecial, '/GetSettingsInstituteListSpecial')

api.add_resource(GetSettingsInstituteWithID, '/GetSettingsInstituteWithID')
api.add_resource(UpdateSettingsInstituteActiveStatus, '/UpdateSettingsInstituteActiveStatus')
api.add_resource(UpdateSettingsInstitute, '/UpdateSettingsInstitute')

api.add_resource(DeleteAllInvoice, '/DeleteAllInvoice')

# ---
api.add_resource(DeleteEverything, '/DeleteEverything')
api.add_resource(DeleteEverythingWithoutSuperAdmin, '/DeleteEverythingWithoutSuperAdmin')
api.add_resource(AddPackageMissingFields, '/AddPackageMissingFields')
api.add_resource(AddSuperAdminMissingFields, '/AddSuperAdminMissingFields')

api.add_resource(InstituteCreateSpecial, '/InstituteCreateSpecial')

api.add_resource(InstituteAPIForDashboard, '/InstituteAPIForDashboard')
api.add_resource(InvoiceAPIForDashboard, '/InvoiceAPIForDashboard')
api.add_resource(GetTotalEmailsCounter, '/GetTotalEmailsCounter')


# -------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', ssl_context=ctx)

