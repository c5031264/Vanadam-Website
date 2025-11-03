# This code imports the Flask library and some functions from it.
import flask
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, g
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect

from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo
import sqlite3, os, hashlib, base64
from dbconstructor import create_database

from HaloData import HI_MAPS

# Create a Flask application instance
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key_for_testing_only")

#cross site protection
csrf = CSRFProtect(app)
#hash object
hash = hashlib.sha256()


#Get DB instance per request, to avoid cross thread errors with db cursor
def get_database():
    if 'db' not in g:

        dbpath = "database.db"
        if os.path.exists(dbpath):
            g.db = sqlite3.connect("database.db")
            print("Connected to database!")
            return g.db
        else:
            print("Database doesn't exist, constructing...")
            create_database()
            conn = sqlite3.connect("database.db")

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

#Construct user validation and registration form classes
class LoginForm(FlaskForm):
    username = StringField('Username',
                            validators=[
                                DataRequired(),
                                Length(min=3, max=16),
                                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', )
                            ])
    password = PasswordField('Password',
                            validators = [
                                DataRequired(),
                                Length(min=8, max=64),
                                Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$')
                            ])
    submit = SubmitField('Login')

#Length and Regexp need checking
class RegisterForm(FlaskForm):
    username = StringField('Username',
                            validators = [
                                DataRequired(message="Username is not Valid."),
                                Length(min=3, max=16, message="Usernames must be between 3 and 16 characters"),
                                Regexp(r'^[A-Za-z][A-Za-a0-9_]*$', message="Usernames must contain letters, spaces or numbers only"),
                            ])
    
    email = EmailField('Email', 
                            validators = [
                                DataRequired(message="Email is not Valid."),
                                Email()
                            ])
    
    password = PasswordField('Password',
                            validators = [
                                DataRequired(),
                                Length(min=8, max=64, message="Password must be between 8 and 64 characters."),
                                Regexp(
                                    r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                    message="Password must contain uppercase, lowercase, number, and symbol."
                                )
                            ])

    password2 = PasswordField('Confirm Password',
                            validators= [
                                DataRequired(),
                                EqualTo('password', message="Passwords must match.")
                            ])

    submit = SubmitField('Register')

# Routes
#===================
# These define which template is loaded, or action is taken, depending on the URL requested
#===================
# Home Page
@app.route('/')
def index():
    return render_template('home.html', title="Vanadam Halo")

@app.route('/article', methods=['GET', 'PATCH', 'POST', 'DELETE'])
def article():
    pass

@app.route('info/<infoType>', methods=['GET'])
def infoPages(infoType):
    # coaching, get involved, etc. not sure if should all have endpoints... (discuss?)
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    db = get_database()
    cur = db.cursor()
    if form.validate_on_submit:  # Checks that submitted login form adheres to input validation rules
        username = form.username.data
        password = form.password.data

        query = "SELECT * FROM users WHERE username = ?"
        cur.execute(query, (username,))
        result = cur.fetchone()
        print(result)

        if result is None:
            print("User not found")
        else:
            if result['password'] == hashlib.sha256(password).hexdigest():
                print("Login successful")
            else:
                print("Login failed")

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    #pop user from session
    pass

@app.route('/mapPage', methods=['GET'])
def mapsAll():
    return render_template('maps.html')

@app.route('/mapPage/<mapID>', methods=['GET'])
def mapPage(mapID):
    print(f'got request for: {mapID}')
    mapID = str(mapID).capitalize()
    map_data = HI_MAPS.get(mapID)
    if not map_data:
        return render_template('siteError.html')
    
    print(map_data)
    return render_template('map.html', map=map_data)

@app.route('/profile/<userID>', methods=['GET', 'PATCH', 'DELETE'])
def profilePage(userName):
    pass

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    #Create db cconnection 
    db = get_database()
    cur = db.cursor()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        query = "SELECT * FROM users WHERE username = ? OR email = ?"
        cur.execute(query, (username, email))
        existing_user = cur.fetchone()

        if existing_user is None:
            hashpass = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashpass))
            db.commit()
            flash("Registration Successful", "success")
            return redirect(url_for('login'))
        else:
            flash("Credentials already taken", "error")
            return redirect(url_for('register'))

    return render_template('register.html', form=form)
  
@app.route('/report', methods=['POST'])
def report():
    pass

@app.route('/videos', methods=['GET, POST'])
def videoSearch(criteria):
    pass

@app.route('/videos/<videoID>', methods=['GET'])
def video(videoID):
    pass

# Run application
#=========================================================
# This code executes when the script is run directly.
if __name__ == '__main__':
    print("Starting Flask application...")
    print("Open Your Application in Your Browser: http://localhost:81")
    # The app will run on port 81, accessible from any local IP address
    app.run(host='0.0.0.0', port=81)
