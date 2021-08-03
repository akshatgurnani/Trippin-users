from flask import Flask, jsonify, request, make_response, redirect, url_for, send_from_directory, abort
import pymongo
import bcrypt, jwt, datetime, uuid, os
from functools import wraps
from pymongo import message
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = './static/images'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secretkeylol'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] =  2 * 1024 * 1024

myClient = pymongo.MongoClient("mongodb+srv://shinchan:cvcvpo123@mycluster1.fzgzf.mongodb.net/tripin?retryWrites=true&w=majority",ssl=True,ssl_cert_reqs='CERT_NONE')
mydb = myClient["tripin"]
users = mydb["user_data"]
Rdata = mydb["review_data"]

# ---------------------------------------------------///////       User routes      ///////////-------------------------------------------------


def token_verify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        

        if not token:
            return jsonify({
                'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.find_one({"_id": data['_id']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        
        return f(current_user, *args, **kwargs)

    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/user_register', methods = ['POST'])
def register():
    qry = {'username': request.args['username']}
    existing_user = users.find_one(qry)

    if existing_user:
        return jsonify({'message':"user already exists"})
        
    else:
        
        #hashpass = bcrypt.hashpw(request.args['password'].encode('utf-8'), bcrypt.gensalt(10))
        salt = bcrypt.gensalt(10)
        hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

        status = users.insert({
            "_id": str(uuid.uuid4()),
            'username': request.args['username'],
            "password": hashpass,
            "name": request.args["name"],
            "email": request.args["email"],
            "mobile_no": request.args["mobile_no"],
            "role": "user",
            })
        if status:
            return jsonify({'message':"user registered successfully"})
        
        return jsonify({"message":"Request cannot be processed. Please  try again later"})


@app.route('/login', methods = ['POST'])
def login():
    login_data = ({
        "username": request.args['username'],
        "password": request.args['password'],
        #"role": request.args['role']
        })
    # if login_data["role"] == 'business':
    #     login_name = bus_data.find_one({"username": login_data["username"]})

    # elif login_data["role"] == 'user':
    login_name = users.find_one({"username": login_data["username"]})

    # else:
    #     return jsonify({"message": "please select for business or not!!"})

    if login_name:
        if bcrypt.checkpw(login_data['password'].encode('utf-8'), login_name['password']):
            token = jwt.encode({'_id': login_name['_id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours = 24)}, app.config['SECRET_KEY'], algorithm="HS256") 
            
            return make_response(jsonify({
                'message': "Login Successfull",
                'token' : token
                }), 201)
        else:
            return jsonify({'message':"username or password does not match"})

    else:
        return make_response("user not found", 401)


@app.route('/me', methods = ['GET'])
@token_verify
def me(current_user):
    # login_data = ({
    #     "username": current_user['username'],
    #     "role": current_user['role']
    #     })

    # dbs = [users, bus_data]
    # for db in dbs:
    #     if (db.find_one({"username": current_user['username']})):
    #         login_data = db.find_one({"username": current_user['username']})

    # if login_data["role"] == 'business':
    #     user = bus_data.find_one({"username": login_data["username"]})

    # elif login_data["role"] == 'user':
    user = users.find_one({"_id": current_user["_id"]})

    json_data = {}

    for keys in user:
        if keys == "password":
            pass 
        else:
            json_data[keys] = user[keys]

    if json_data:
        return jsonify(json_data)

    else:
        return jsonify({"message":"request cannot be processed, please try again!!"})

@app.route('/upload_images', methods=['POST'])
@token_verify
def upload_file(current_user):
    user = users.find_one({"_id": current_user['_id']})

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"message":'no file part'})

        file = request.files['file']

        if file.filename == '':
            return jsonify({"message":'no file selected'})

        if file and allowed_file(file.filename):
            new_name =user['_id'] + '.jpg'
            filename = secure_filename(new_name)
            #file.save(os.path.join(app.config['UPLOAD_FOLDER'], user['_id']) + '.' + filename.rsplit('.', 1)[1].lower())
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({"message":'file uploaded successfully'})

    # elif request.method == 'GET':

    #     img = user['_id']
    #     img = f"{img}.jpg"
    #     #return str(img)
    #     try:
    #         return send_from_directory(app.config["UPLOAD_FOLDER"], filename=img, as_attachment=True)
    #     except FileNotFoundError:
    #         abort(404)

@app.route('/update', methods = ['PUT'])
@token_verify
def me_update(current_user):
    # login_data = ({
    #     "username": current_user['username'],
    #     "role": current_user['role']
    #     })
    # if login_data["role"] == 'business':
    #     user = bus_data.find_one({"username": login_data["username"]})

    #     myQuery = {"username": user['username']}

    #     get_new_data =  request.get_json()
    #     new_data = {"$set":{}}

    #     for key in get_new_data:
    #         new_data["$set"][key] = get_new_data[key]

    
    #     status = bus_data.update_one(myQuery, new_data)
    #     if status:
    #         return jsonify({'message': "updated successfully"})

    #     return jsonify({"message":"request cannot be processed, please try again!!"})

    #elif login_data["role"] == 'user':
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}

    get_new_data =  request.get_json()
    new_data = {"$set":{}}

    for key in get_new_data:
        new_data["$set"][key] = get_new_data[key]

    
    status = users.update_one(myQuery, new_data)
    if status:
        return jsonify({'message': "updated successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})

@app.route('/delete_user', methods = ['DELETE'])
@token_verify
def delete_user(current_user):
    # login_data = ({
    #     "username": current_user['username'],
    #     "role": current_user['role']
    #     })
    # if login_data["role"] == 'business':
    #     user = bus_data.find_one({"username": login_data["username"]})

    #     myQuery = {"username": user['username']}
    #     status = bus_data.delete_one(myQuery)

    #     if status:
    #         return jsonify({'message': "record deleted successfully"})

    #     return jsonify({"message":"request cannot be processed, please try again!!"})

    #elif login_data["role"] == 'user':
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}
    status = users.delete_one(myQuery)

    if status:
        return jsonify({'message': "record deleted successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})




# ---------------------------------------------//////////          Business routes         //////////------------------------------------------------

@app.route('/business_register', methods = ['POST'])
def business_register():
    qry = {'username': request.args['username']}
    existing_user = users.find_one(qry)

    if existing_user:
        return jsonify({'message':"user already exists"})
        
    else:
        salt = bcrypt.gensalt(10)
        hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

        status = users.insert({
            "_id": str(uuid.uuid4()),
            "username": request.args["username"],
            "password": hashpass,
            "name": request.args["name"],
            "email": request.args["email"],
            "mobile_no": request.args["mobile_no"],
            "address": request.args["address"],
            "desc": request.args["desc"],
            "city": request.args["city"],
            "type": request.args["type"],
            "role": "business",
            })

        if status:
            return jsonify({'message':"business registered successfully"})

        return jsonify({"message":'please try again'})

@app.route('/places', methods = ['GET'])
def places():
    loc = request.args['city']

    myQuery = {"city": loc}
    # display_data = {
    #     "name": 1,
    #     "email": 1,
    #     "mobile_no": 1,
    #     "address": 1,
    #     "desc": 1,
    #     "location": 1,
    #     "type": 1,
    # }
    display_data = {
        "username": 0,
        "password": 0,
        "role": 0,
    }
    for locs in users.find(myQuery, display_data):
        return jsonify(locs)

    else:
        return jsonify({"message": "no places to visit at this location :("})

@app.route("/getimage/<path:id>",methods = ['GET'])
def get_image(id):

    img = f"{id}.jpg"
    try:
        #return send_from_directory(app.config["UPLOAD_FOLDER"], filename=image_name, as_attachment=True)
        return redirect(url_for('static', filename='images/' + img), code=301)
    except FileNotFoundError:
        abort(404)


# -----------------------------///////////////////              review routes               //////////////----------------------------------------


@app.route("/post_reviews",methods = ['POST'])
@token_verify
def post_reviews():
    review_data =  request.get_json()
    status = Rdata.insert(review_data)

    if status:
            return jsonify({'message':"Review registered successfully"})

    return jsonify({"message":'please try again'})


@app.route("/get_reviews/<path:id>",methods = ['GET'])
def get_reviews(id):
    myQuery = {}
    if id == Rdata['user_id']:
        myQuery = {"user_id": id}
        # display_data = {
        #     "_id": 0,
        #     # "user_id": 1,
        #     # "business_id": 1,
        #     # "business_name": 1,
        #     # "review_desc": 1,
        #     # "ratings": 1,
        # }

    elif id == Rdata['business_id']:
        myQuery = {"business_id": id}

    display_data = {
        "_id": 0,
        # "user_id": 1,
        # "business_id": 1,
        # "business_name": 1,
        # "review_desc": 1,
        # "ratings": 1,
    }
    for locs in Rdata.find(myQuery, display_data):
        return jsonify(locs)

    else:
        return jsonify({"message": "no reviews yet :("})

@app.route("/update_reviews",methods = ['PUT'])
@token_verify
def update_reviews(current_user):
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"user_id": user['_id']}

    get_new_data =  request.get_json()
    new_data = {"$set":{}}

    for key in get_new_data:
        new_data["$set"][key] = get_new_data[key]

    
    status = Rdata.update_one(myQuery, new_data)
    if status:
        return jsonify({'message': "updated successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})


@app.route('/delete_rerview', methods = ['DELETE'])
@token_verify
def delete_review(current_user):
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}
    status = Rdata.delete_one(myQuery)

    if status:
        return jsonify({'message': "Review deleted successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})


@app.route("/avg_ratings",methods = ['GET'])
def average():
    raw_data = request.get_json()
    if raw_data == ' ':
        return jsonify({"message": "Data not found. List is empty"})

    lst = raw_data['total']
    total_count = len(lst)
    total = sum(lst)

    avg = total / total_count
    result = round(avg, 1)
    if result == '':
        return jsonify({"message": 'request cannot be processed, please try again!!'})
        
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)
