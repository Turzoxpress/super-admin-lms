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