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