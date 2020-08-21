import json

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

from bson import BSON
from bson import json_util

from pprint import pprint

app = Flask(__name__)
api = Api(app)

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
            "msg": "Welcome LMS super admin! Your API server is working successfully!"
        }
        return jsonify(retJson)


def UserExist(username):
    if superad.find({"username": username}).count() == 0:
        return False
    else:
        return True

# -- Register new super admin
class RegisterSuperAdmin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'User already exists,Try with a new one!'
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store username and pw into the database
        superad.insert_one({
            "username": username,
            "password": hashed_pw

        })

        retJson = {
            "status": 200,
            "msg": "New Super Admin added successfully!"
        }

        return jsonify(retJson)



def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = superad.find({
        "username":username
    })[0]["password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

# -- Super admin login
class SuperAdminLogin(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        username = postedData["username"]
        password = postedData["password"]

        if not UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'No user with with username'
            }
            return jsonify(retJson)

        if not verifyPw(username,password):
            retJson = {
                'status': 301,
                'msg': 'Wrong username or password'
            }
            return jsonify(retJson)

        retJson = {
            'status': 200,
            'msg': 'Login successful! Welcome '+username
        }
        return jsonify(retJson)


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


# -- test


class Test(Resource):
    def post(self):
        postedData = request.get_json()

        # Get the data
        data = postedData["data"]

        test.insert_one(
            {
                "data": data
            }
        )

        cursor = test.find()
        holder = []
        for i in cursor:
            holder.append(i)

        retJson = {
            "status": 200,
            "msg": str(holder)
        }

        return jsonify(retJson)


# -----------------------------------------------------------------------


api.add_resource(Welcome, '/welcome')
api.add_resource(RegisterSuperAdmin, '/register_super_admin')
api.add_resource(ShowAllSuperAdmin, '/show_all_super_admin')
api.add_resource(Test, '/test')
api.add_resource(DeleteAllData, '/delete_all_data')
api.add_resource(SuperAdminLogin, '/super_admin_login')

# -----------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
