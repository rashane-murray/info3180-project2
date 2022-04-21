"""
Flask Documentation:     https://flask.palletsprojects.com/
Jinja2 Documentation:    https://jinja.palletsprojects.com/
Werkzeug Documentation:  https://werkzeug.palletsprojects.com/
This file creates your application.
"""
import os
from app import app
from flask import render_template, request, jsonify, send_from_directory, g
from flask_login import login_user, logout_user, current_user, login_required
from .forms import *
from .models import *
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime


#JWT decorator. Checks for a valid JWT token
def requires_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return jsonify(
                {'message': 'Authorization header is expected'}), 401
        parts = auth.split()
        if parts[0].lower() != 'bearer':
            return jsonify(
                {'message': 'Authorization header must start with Bearer'}
            ), 401
        elif len(parts) == 1:
            return jsonify({'message': 'Token not found'}), 401
        elif len(parts) > 2:
            return jsonify({'message': 'Authorization header must be Bearer + \s + token'}), 401
        token = parts[1]
        try:
            payload = jwt.decode(token, app.config.get(
                'SECRET_KEY'), algorithms="HS256")
            # may be changed when auth is complete
            current_user = User.query.get(payload.get('id'))
            if not current_user:
                return jsonify({'message': "Token is invalid, no user matched to token"}), 401
        except jwt.InvalidSignatureError:
            return jsonify({'message': 'Token is invalid'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token is expired'}), 401
        except jwt.DecodeError:
            return jsonify({'message': 'Token signature is invalid'}), 401
        g.current_user = current_user
        return f(*args, **kwargs)
    return decorated


###
# Routing for your application.
###

@app.route('/')
def index():
    return jsonify(message="This is the beginning of our API")



# API Routes Start


@app.route('/api/register', methods=['POST'])
def register():
    form = SignupForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
            email = form.email.data
            name = form.name.data
            location = form.location.data
            bio = form.biography.data
            photo = form.photo.data
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            db.session.add(Users(username, password, name, email, location, bio, filename))
            db.session.commit() 
            return jsonify({ 'message': 'User Succesfully Added =)'})           
        return jsonify({'errors': form_errors(form)})
    return jsonify({'error_message': 'Method Not Allowed'})




@app.route('/api/auth/login',methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = Users.query.filter_by(username=username).first()
            if user is not None and check_password_hash(user.password,password):
                login_user(user)
                payload = {
                    'id': user.id,
                    'username': user.username,
                    'iat': datetime.datetime.now(datetime.timezone.utc),
                    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=45)
                }
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
                return jsonify({"login_message" : "Logged in Successfully", 'token': token, 'id': user.id})
            else:
                return jsonify({"error_message" : "Username or Password is incorect"})
        return jsonify({"errors": form_errors(form)})  
    return jsonify({"error_message" : "Method not allowed"})




@app.route('/api/auth/logout', methods=['POST'])
@requires_token
def logout():
    logout_user()
    return jsonify({"message" : "Log out successful"}) #Logout Message




@app.route('/api/cars', methods=['GET'])
@requires_token
def getcars():
    if request.method == 'GET':
        cars = db.session.query(Cars).order_by(Cars.cid.desc()).all()
        if cars is None:
            return jsonify({"error_message": "No cars in database"})
        else:
            carList = []
            for car in cars:
                carList.append({
                    "cid": car.cid,
                    "description": car.description,
                    "year": car.year,
                    "make": car.make,
                    "model": car.model,
                    "colour": car.colour,
                    "transmission": car.transmission,
                    "car_type": car.car_type,
                    "price": car.price,
                    "photo": "/uploads/" + car.photo,
                    "user_id": car.user_id
                })
            return jsonify({"car_results": cars})




@app.route('/api/cars', methods=['POST'])
@requires_token
def addcars():
    form = AddCarForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            make = form.make.data
            model = form.model.data
            colour = form.colour.data
            year = form.year.data
            price = form.price.data
            car_type = form.car_type.data
            transmission = form.transmission.data
            description = form.description.data
            photo = form.photo.data
            user_id = current_user.uid

            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            newCar = Cars(make, model, colour, year, price, car_type, transmission, description, filename, user_id) 
            db.session.add(newCar)
            db.session.commit()

            return jsonify({"description": description, "year": year, "make": make, "model": model, "colour": colour, "transmission": transmission,"car_type" : car_type, "price": price, "photo": filename, "user_id": user_id})
        return jsonify({"errors": form_errors(form)})



@app.route('/api/cars/<int:car_id>', methods=['GET'])
@requires_token
def getcar(car_id):
    if request.method == 'GET':
        result = db.session.query(Cars).filter_by(cid=car_id).first()
        if result is None:
            return jsonify({"error_message": "No match"})
        else:
            uid = current_user.uid
            check = db.session.query(Favourites).filter(Favourites.user_id == uid, Favourites.car_id == car_id).first()
            if check == None:
                isFav = False
            else:
                isFav = True
            car = {"cid": result.cid,
                    "description": result.description, "year": result.year, "make": result.make, "model": result.model, "colour": result.colour, "transmission": result.transmission, "car_type": result.car_type, "price": result.price, "photo": "/uploads/" + result.photo, "user_id": result.user_id, "favourite": isFav}
            return jsonify({"data": car})
    return jsonify({'error_message': 'Method Not Allowed'})



#Add a favourite and unfavourite route



@app.route('/api/search', methods=['GET'])
@requires_token
def search():
    if request.method == 'GET':
        make = request.args.get('make')
        model = request.args.get('model')
        if (make == "") and (model != ""):
            cars = Cars.query.filter_by(model=model).all()
        elif (make != "") and (model == ""):
            cars = Cars.query.filter_by(make=make).all()
        elif (make != "") and (model != ""):
            cars = Cars.query.filter_by(make=make,model=model).all()
        else:
            cars = db.session.query(Cars).all()
        if cars is None:
            return jsonify({"error_message": "No search results are available"})
        else:
            carList = [] 
            for car in cars:
                carList.append({"cid": car.cid, "description": car.description, "year": car.year, "make": car.make, "model": car.model, "colour": car.colour, "transmission": car.transmission, "car_type": car.car_type, "price": car.price, "photo": "/uploads/" + car.photo, "user_id": car.user_id})
            return jsonify({"car_list": carList})
    return jsonify({"error_message": 'Method Not Allowed'})



@app.route('/api/users/<int:user_id>', methods=['GET'])
@requires_token
def getuser(user_id):
    if request.method == 'GET':
        user = db.session.query(Users).filter_by(uid=user_id).first()
        if user is None:
            return jsonify({"error_message": "User cannot be found."})
        else:
            userInfo = {"id": user.uid, "username": user.username, "name": user.name, "photo": '/uploads/' + user.photo, "email": user.email, "location": user.location, "biography": user.biography, "date_joined": user.date_joined}
            return jsonify({"user_info": userInfo})
    return jsonify({"error_message": "Method Not Allowed"})
        
        

@app.route('/api/users/<int:user_id>/favourites', methods=['GET'])
@requires_token
def getfavs(user_id):
    if request.method == 'GET':
        favs = db.session.query(Favourites).filter(Favourites.user_id ==user_id).all()
        if favs is None:
            return jsonify({"error_message": "User has no favourites."})
        else: 
            favList = []
            for fav in favs:
                car = db.session.query(Cars).filter(Cars.cid==fav.car_id).first()
                favList.append({"cid": car.cid, "description": car.description, "year": car.year, "make": car.make, "model": car.model, "colour": car.colour, "transmission": car.transmission, "car_type": car.car_type, "price": car.price, "photo": "/uploads/" + car.photo, "user_id": car.user_id})
            return jsonify({"favourite_cars": favList})
    return jsonify({'error_message': 'Method Not Allowed'})

# API Routes End



###
# The functions below should be applicable to all Flask apps.
###

# Here we define a function to collect form errors from Flask-WTF
# which we can later use
def form_errors(form):
    error_messages = []
    """Collects form errors"""
    for field, errors in form.errors.items():
        for error in errors:
            message = u"Error in the %s field - %s" % (
                    getattr(form, field).label.text,
                    error
                )
            error_messages.append(message)

    return error_messages

@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also tell the browser not to cache the rendered page. If we wanted
    to we could change max-age to 600 seconds which would be 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return jsonify(error="Page Not Found"), 404




if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port="8080")