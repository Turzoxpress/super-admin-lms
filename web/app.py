import json
import os

from flask import Flask, jsonify, request, make_response, redirect, url_for, flash, render_template
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
api = Api(app)
app.config['JSON_SORT_KEYS'] = False
secret_key = "bangladesh"

client = MongoClient("mongodb://db:27017")
db = client["SuperAdminDB"]
superad = db["SuperAdmin"]
tokenbank = db["tokenbank"]
test = db["test"]

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# -- Welcome API
class Welcome(Resource):
    def get(self):
        # Show a welcome greetings
        retJson = {
            "status": 200,
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


# -- Register new super admin
class RegisterSuperAdmin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        email = postedData["email"]
        password = postedData["password"]

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
            "created_at": datetime.today().strftime('%d-%m-%Y')

        })

        retJson = {
            "status": 200,
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
            "status": 200,
            "data": str(holder)
        }

        return jsonify(retJson)


# -- Delete all super admins
class DeleteAllData(Resource):
    def get(self):
        superad.drop()

        retJson = {
            "status": 200,
            "msg": "All collection data deleted successfully!"
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
            retJson = {
                'status': 301,
                'msg': 'No user with with username'
            }
            return jsonify(retJson)

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

        # -- Generate an access token
        retJson = {
            'status': "ok",
            'msg': {
                "id": str(userid),
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
        "status": 200,
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
                # return 'Ready to do next job'
                hashed_pw = superad.find({
                    "email": which_user
                })[0]["password"]

                if bcrypt.hashpw(old_password.encode('utf8'), hashed_pw) == hashed_pw:
                    # return 'Ready to do next job'
                    hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

                    myquery = {"email": which_user}
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            # get the data
            postedData = request.get_json()

            # Get the data
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

            myquery = {"email": which_user}
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
    def get(self):
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = superad.find({"email": which_user})
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            # get the data
            postedData = request.get_json()

            # Get the data
            address = postedData["address"]
            post_office = postedData["post_office"]
            post_code = postedData["post_code"]
            thana = postedData["thana"]
            district = postedData["district"]
            division = postedData["division"]
            per_address = postedData["per_address"]
            per_post_office = postedData["per_post_office"]
            per_post_code = postedData["per_post_code"]
            per_thana = postedData["per_thana"]
            per_district = postedData["per_district"]
            per_division = postedData["per_division"]

            myquery = {"email": which_user}
            newvalues = {"$set": {
                "address": address,
                "post_office": post_office,
                "post_code": post_code,
                "thana": thana,
                "district": district,
                "division": division,
                "per_address": per_address,
                "per_post_office": per_post_office,
                "per_post_code": per_post_code,
                "per_thana": per_thana,
                "per_district": per_district,
                "per_division": per_division,
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
    def get(self):
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

            result = superad.find({"email": which_user})
            holder = []
            user_data = {}
            for i in result:
                # user_data = {}
                user_data["id"] = str(i["_id"])
                user_data["user_id"] = str(i["_id"])
                user_data["address"] = str(i["address"])
                user_data["post_office"] = str(i["post_office"])
                user_data["post_code"] = str(i["post_code"])
                user_data["thana"] = str(i["thana"])
                user_data["district"] = str(i["district"])
                user_data["division"] = str(i["division"])
                user_data["per_address"] = str(i["per_address"])
                user_data["per_post_office"] = str(i["per_post_office"])
                user_data["per_post_code"] = str(i["per_post_code"])
                user_data["per_thana"] = str(i["per_thana"])
                user_data["per_district"] = str(i["per_district"])
                user_data["per_division"] = str(i["per_division"])
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

                # work to do
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
                    filename = str(time.time_ns()) + file.filename  # secure_filename(file.filename)
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

                    # return data['link']
                    # return (str(j1))
                    myquery = {"email": which_user}
                    newvalues = {"$set": {
                        "avatar_img": data['link'],
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    superad.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Avatar image updated"
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

            # Check user with email
            if not UserExist(which_user):
                retJson = {
                    "status": "failed",
                    "msg": "Invalid access token"
                }

                return jsonify(retJson)

                # work to do
            if request.method == 'POST':
                # check if the post request has the file part
                if 'cover_img' not in request.files:
                    flash('No file part')
                    return redirect(request.url)
                file = request.files['cover_img']
                # if user does not select file, browser also
                # submit an empty part without filename
                if file.filename == '':
                    flash('No selected file')
                    return redirect(request.url)
                if file and allowed_file(file.filename):
                    filename = str(time.time_ns()) + file.filename  # secure_filename(file.filename)
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

                    # return data['link']
                    # return (str(j1))
                    myquery = {"email": which_user}
                    newvalues = {"$set": {
                        "cover_img": data['link'],
                        "updated_at": datetime.today().strftime('%d-%m-%Y')
                    }}

                    superad.update_one(myquery, newvalues)

                    retJson = {
                        "status": "ok",
                        "msg": "Cover image updated"
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
            #"tokenStatus": str(isTokenInserted)
        }

        return jsonify(retJosn)


class SuperAdminPasswordResetReedemByEmail(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        token = postedData["token"]
        email = postedData["email"]
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

        # Check user with email
        if not UserExist(email):
            retJson = {
                "status": "failed",
                "msg": "Email not exists"
            }

            return jsonify(retJson)

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
            #"token_status": str(isTokenDeleted)
        }
        return jsonify(retJson)


class AWSSender(Resource):
    def get(self):
        smtp = smtplib.SMTP('email-smtp.us-east-2.amazonaws.com')

        smtp.connect('email-smtp.us-east-2.amazonaws.com', 25)

        smtp.starttls()

        smtp.login('AKIAUWJ6HWYKQOPXBNFT', 'BGY/sFIu1up+j/HvTaCPQQjFRuN3w1v46qpFTroG4j7j')

        response = smtp.sendmail('customer_support_lms@brlbd.com', 'turzoxpress@gmail.com', 'welcome')

        return jsonify(str(response))


class TestPhpRequest(Resource):
    def get(self):
        url = "http://tuembd.com/test_mail.php"
        payload = {
            "email": "turzoxpress@gmail.com",
            "token": "sdfsdfsdfdsfsdfdsf"
        }
        headers = {
            'Content-Type': 'application/json'
        }

        x = requests.post(url, headers=headers,
                          data=payload)

        return jsonify(str(x.text))


# -----------------------------------------------------------------------


api.add_resource(Welcome, '/welcome')
api.add_resource(RegisterSuperAdmin, '/register_super_admin')
api.add_resource(ShowAllSuperAdmin, '/show_all_super_admin')
api.add_resource(DeleteAllData, '/delete_all_data')

api.add_resource(SuperAdminLogin, '/super_admin_login')
api.add_resource(SuperAdminLogOut, '/super_admin_logout')
api.add_resource(UpdateSuperAdminPassword, '/super_admin_password_update')
api.add_resource(SuperAdminProfileInfoUpdate, '/super_admin_profile_info_update')
api.add_resource(GetSuperAdminProfileInfo, '/get_super_admin_profile_info')
api.add_resource(SuperAdminAddressUpdate, '/super_user_address_update')
api.add_resource(GetSuperAdminAddress, '/get_super_admin_address')
api.add_resource(SuperAdminAvatarImageUpload, '/super_admin_avatar_upload')
api.add_resource(SuperAdminCoverImageUpload, '/super_admin_cover_upload')
api.add_resource(SuperAdminPasswordResetRequestByEmail, '/super_admin_email_password_reset_request')
api.add_resource(AWSSender, '/test_mail')
api.add_resource(TestPhpRequest, '/test_php')
api.add_resource(SuperAdminPasswordResetReedemByEmail, '/super_admin_password_redeem_email')

# -----------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
