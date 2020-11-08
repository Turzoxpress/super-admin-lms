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