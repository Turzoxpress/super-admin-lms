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