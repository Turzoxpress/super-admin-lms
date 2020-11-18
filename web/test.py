for i in data:
    myquery = {"_id": ObjectId(i["_id"])}
    newvalues = {"$set": {
        "package.monthly_service_charge": "800",
        "package.total_amount": "12800",
        "package.discounted_amount": "800"
    }}

    packagecol.update_one(myquery, newvalues)





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