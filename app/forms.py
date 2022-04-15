from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, FloatField, FileField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email
from flask_wtf.file import FileField,FileRequired,FileAllowed

class LoginForm(FlaskForm):
    username = StringField("Username", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])

class SignupForm(FlaskForm):
    username = StringField("Username", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])
    name = StringField("Full Name", validators = [DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    location = StringField("Location", validators = [DataRequired()])
    biography = TextAreaField("Biography", validators = [DataRequired()])
    photo = FileField("Photo", validators=[FileRequired(), FileAllowed(['jpg','png'])])

class AddCarForm(FlaskForm):
    make = StringField("Make", validators = [DataRequired(), ])
    model = StringField("Model", validators = [DataRequired(), ])
    colour = StringField("Colour", validators = [DataRequired()])
    year = StringField("Year", validators = [DataRequired()])
    price= FloatField("Price", validators = [DataRequired()])
    car_type = SelectField("Car Type", choices=[('Sedan', 'Sedan'), ('Coupe', 'Coupe'), ('Sports Car', 'Sports Car'), ('Station Wagon', 'Station Wagon'), ('Hatchback', 'Hatchback'), ('Convertible', 'Convertible'), ('SUV', 'SUV'), ('Minivan', 'Minivan'), ('Pickup Truck', 'Pickup Truck'), ('Jeep', 'Jeep'), ('Electric', 'Electric')])
    transmission = SelectField("Transmission", choices=[('Automatic', 'Automatic'), ('Manual', 'Manual')])
    description = TextAreaField("Descripton", validators = [DataRequired()])
    photo = FileField("Photo", validators=[FileRequired(), FileAllowed(['jpg','png','jpeg'])])