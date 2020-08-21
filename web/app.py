import json
from base64 import b64decode

from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
api = Api(app)
app.config['JSON_SORT_KEYS'] = False
secret_key = "bangladesh"

client = MongoClient("mongodb://db:27017")
db = client["SuperAdminDB"]
superad = db["SuperAdmin"]
test = db["test"]


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
            "password": hashed_pw

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

        # -- Generate an access token
        retJson = {
            'status': "ok",
            'msg': {
                "id": 2,
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
                    newvalues = {"$set": {"password": hashed_pw}}

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


# -----------------------------------------------------------------------


api.add_resource(Welcome, '/welcome')
api.add_resource(RegisterSuperAdmin, '/register_super_admin')
api.add_resource(ShowAllSuperAdmin, '/show_all_super_admin')
api.add_resource(DeleteAllData, '/delete_all_data')

api.add_resource(SuperAdminLogin, '/super_admin_login')
api.add_resource(SuperAdminLogOut, '/super_admin_logout')
api.add_resource(UpdateSuperAdminPassword, '/super_admin_password_update')

# -----------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
