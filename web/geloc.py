import json


def getDivisions():
    # Opening JSON file
    with open('division.json') as json_file:
        data = json.load(json_file)
        return data


def getDistrict(id):
    # Opening JSON file
    with open('district.json') as json_file:
        data = json.load(json_file)

        result = data['districts']

        holder = []
        for i in result:
            if i["division_id"] == str(id):
                data2 = {
                    "id": str(i["id"]),
                    "division_id": str(i["division_id"]),
                    "name": str(i["name"]),
                    "bn_name": str(i["bn_name"]),
                    "lat": str(i["lat"]),
                    "long": str(i["long"])

                }

                holder.append(data2)

        return holder


def getUpazilla(id):
  # Opening JSON file
  with open('upazilla.json') as json_file:
    data = json.load(json_file)

    result = data['upazilas']

    holder = []
    for i in result:
      if i["district_id"] == str(id):
        data2 = {
          "id": str(i["id"]),
          "district_id": str(i["district_id"]),
          "name": str(i["name"]),
          "bn_name": str(i["bn_name"])

        }

        holder.append(data2)

    return holder
