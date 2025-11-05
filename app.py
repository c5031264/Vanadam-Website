# This code imports the Flask library and some functions from it.
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
        if not os.path.exists(dbpath):
            create_database()

        g.db = sqlite3.connect("database.db")
        g.db.row_factory = sqlite3.Row

        print("Connected to database!")
        return g.db

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
                                #Length(min=3, max=16),
                                #Regexp('^[A-Za-z][A-Za-z0-9_.]*$', )
                            ])
    password = PasswordField('Password',
                            validators = [
                                DataRequired(),
                                #Length(min=8, max=64),
                                #Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$')
                            ])
    submit = SubmitField('Login')

#Length and Regexp need checking
class RegisterForm(FlaskForm):
    username = StringField('Username',
                            validators = [
                                DataRequired(message="Username is not Valid."),
                                #Length(min=3, max=16, message="Usernames must be between 3 and 16 characters"),
                                #Regexp(r'^[A-Za-z][A-Za-a0-9_]*$', message="Usernames must contain letters, spaces or numbers only"),
                            ])
    
    email = EmailField('Email', 
                            validators = [
                                DataRequired(message="Email is not Valid."),
                                #Email()
                            ])
    
    password = PasswordField('Password',
                            validators = [
                                DataRequired(),
                                #Length(min=8, max=64, message="Password must be between 8 and 64 characters."),
                                #Regexp(
                                #    r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                #    message="Password must contain uppercase, lowercase, number, and symbol."
                                #)
                            ])

    password2 = PasswordField('Confirm Password',
                            validators= [
                                DataRequired(),
                                #EqualTo('password', message="Passwords must match.")
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

@app.route('/info/<infoType>', methods=['GET'])
def infoPages(infoType):
    # coaching, get involved, etc. not sure if should all have endpoints... (discuss?)
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if 'username' in session:
        print("Already logged in")
        return redirect(url_for('index'))

    db = get_database()
    cur = db.cursor()
    if form.validate_on_submit():  # Checks that submitted login form adheres to input validation rules
        username = form.username.data
        password = form.password.data

        query = "SELECT * FROM users WHERE username = ?"
        cur.execute(query, (username,))
        result = cur.fetchone()

        if result is None:
            print("User not found")
            return render_template('login.html', form=form)
        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        stored_password = result['password']

        if hashed_input == stored_password:
            #Clear session data to remove stale data, then fill in session data
            session.clear()
            session['username'] = result['username']
            flash("Login successful!", "success")

            return redirect(url_for('index'))
        else:
            flash("Incorrect password.", "error")

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('logged_in', None)

    flash("You’ve been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    print("0")
    form = RegisterForm()
    # Create db connection and cursor
    db = get_database()
    cur = db.cursor()

    if form.validate_on_submit():  # If form passes validation rules
        # Retrieve inputs from form
        username = form.username.data
        email = form.email.data
        password = form.password.data
        password2 = form.password2.data

        if password != password2:
            flash("Passwords don't match!", "error")
            return render_template('register.html', form=form)

        query = "SELECT * FROM users WHERE username = ? OR email = ?"
        cur.execute(query, (username, email))
        existing_user = cur.fetchone()

        if existing_user is None:
            # Hash password and insert new user record
            hashpass = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashpass))
            db.commit()

            flash("Registration Successful", "success")
            session['username'] = username

            return redirect(url_for('index'))
        else:
            flash("Credentials already taken", "error")
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/mapPage', methods=['GET'])
def mapsAll():
    return render_template('maps.html')

@app.route('/mapPage/<mapID>', methods=['GET'])
def mapPage(mapID):
    print(f'got request for: {mapID}')
    mapID = str(mapID).capitalize()
    map_data = HI_MAPS.get(mapID)
    if not map_data:
        print(f'user attempted to access map variant: {mapID} but it doesnt exist. redirecting to siteError.HTML')
        return render_template('siteError.html')
    
    print(map_data)
    return render_template('map.html', map=map_data)

@app.route('/profile/<userID>', methods=['GET', 'PATCH', 'DELETE'])
def profilePage(username):
    pass


@app.route('/report', methods=['POST'])
def report():
    pass

@app.route('/search', methods=['GET, POST'])
def search(criteria):
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
