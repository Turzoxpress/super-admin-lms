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