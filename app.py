# This code imports the Flask library and some functions from it.
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, g
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect

import dbconstructor
from flask_session import Session

from wtforms import EmailField, PasswordField, StringField, SelectMultipleField, SelectField, SubmitField, IntegerField, widgets
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo, Optional

import sqlite3, os, hashlib, base64
from dbconstructor import create_database

from HaloData import HI_MAPS
from formclasses import LoginForm, RegisterForm, SearchForm

# Create a Flask application instance
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key_for_testing_only")
app.config.from_pyfile("config.py")

# temp folder for storing session files (make SQL?)
SESSION_DIR = './flask_session'
os.makedirs(SESSION_DIR, exist_ok=True)

#cross site protection
csrf = CSRFProtect(app)
Session(app)

#hash object
hash = hashlib.sha256()

dbpath = "database.db"
if not os.path.exists(dbpath):
    dbconstructor.create_database()

#Get DB instance per request, g is a flask object, which stores stuff for the lifetime of a request
#Prevents the connection from being started from one CPU thread and accessed in another, raising an error
def get_database():
    if 'db' not in g:
        dbpath = "database.db"
        if not os.path.exists(dbpath):
            dbconstructor.create_database()

        g.db = sqlite3.connect("database.db")
        g.db.row_factory = sqlite3.Row

        print("Connected to database!")
    return g.db

#This route is called at the end of a request, removing db connection from g, ready for the next request
@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Routes
#===================
# These define which template is loaded, or action is taken, depending on the URL requested
#===================
# Home Page
@app.route('/')
def index():
    if not session.get("name"):
        print(session)
    print(session)
    return render_template('home.html', title="Vanadam Halo")


#===================
#Registration & Validation
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "GET" and 'username' in session:
            print("Already logged in")
            flash("Cannot log in while already logged in.", "error")   
            return redirect(url_for('index'))

    db = get_database()
    cur = db.cursor()
    if form.validate_on_submit():  # Checks that submitted login form adheres to input validation rules
        username = form.username.data
        password = form.password.data

        query = "SELECT * FROM Users WHERE username = ?"
        cur.execute(query, (username,))
        result = cur.fetchone()

        if result is None:
            print("User not found")
            flash("Incorrect username or password.", "error")
            return render_template('login.html', form=form)
        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        stored_password = result['password']

        if hashed_input == stored_password:
            #Clear session data to remove stale data, then fill in session data
            session.clear()
            session['username'] = result['username']
            flash(f"Logged in as {session['username']}", "success")

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
    if request.method == "GET" and 'username' in session:
            print("Already logged in")
            flash("Cannot register a new account while already logged in.", "error")   
            return redirect(url_for('index'))
    
    print("RegisterForm has been sent to server")
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
        print("RegisterForm has been validated")
        if password != password2:
            flash("Passwords don't match!", "error")
            return render_template('register.html', form=form)

        query = "SELECT * FROM Users WHERE username = ? OR email = ?"
        cur.execute(query, (username, email))
        existing_user = cur.fetchone()

        if existing_user is None:
            # Hash password and insert new user record
            hashpass = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("INSERT INTO Users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashpass))
            db.commit()

            flash("Registration Successful", "success")
            session['username'] = username

            return redirect(url_for('index'))
        else:
            flash("Credentials already taken", "error")
            return redirect(url_for('register'))

    return render_template('register.html', form=form)
#===================
#Content
@app.route('/article', methods=['GET', 'PATCH', 'POST', 'DELETE'])
def article():
    pass

@app.route('/info/<infoType>', methods=['GET'])
def infoPages(infoType):
    # coaching, get involved, etc. not sure if should all have endpoints... (discuss?)
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
        print(f'user attempted to access map variant: {mapID} but it doesnt exist. redirecting to siteError.HTML')
        return render_template('siteError.html')
    
    print(map_data)
    return render_template('map.html', map=map_data)

@app.route('/profile/<username>', methods=['GET', 'PATCH', 'DELETE'])
def profilePage(username):
    logged_in_user = session.get('username')
    print(f"session username:", logged_in_user)

    if not logged_in_user:
        flash("you must be logged in to view your profile", "error")
        return redirect(url_for('index'))

    if username != logged_in_user:
        flash("sneaky! you can only view your own profile at the moment!", "error")
        return redirect(url_for('index'))
    
    print(f"got request to load profile page for: {logged_in_user}")
    return render_template('profile.html', username=logged_in_user)


@app.route('/report', methods=['POST'])
def report():
    pass

@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        # Extract form data variables
        #General Filters
        date = form.date.data
        if date is None:
            #date=todaysdate
            pass
        date_selector = form.date_selector.data #Determines wether to search for posts before, after or on given date

        tags = form.tags.data #Array of tags
        #Blog filters
        original_poster = form.original_poster.data
        #Video Filters
        vid_type = form.vid_type.data
        selected_games = form.games.data #Array of games
        selected_maps = form.maps.data #Array of maps
        gamemode = form.gamemode.data
        min_mmr = form.min_mmr.data
        if min_mmr is None:
            min_mmr = 0
        max_mmr = form.max_mmr.data
        if max_mmr is None:
            max_mmr = 9999

        # Print for debugging
        print("Date:", date)
        print("Date Selector:", date_selector)

        print("Tags:", tags)

        print("Original Poster:", original_poster)
        print("Video Type:", vid_type)
        print("Selected Games:", selected_games)
        print("Selected Maps:", selected_maps)
        print("Game Mode:", gamemode)
        print("Min MMR:", min_mmr)
        print("Max MMR:", max_mmr)

        db = get_database()
        cur = db.cursor()

        #SQL
        query = ("")
        params = []
        if date_selector == 'On':
            query += ("SELECT * FROM Posts WHERE date = ?")
            params.append(date)
        elif date_selector == 'Before':
            query += ("SELECT * FROM Posts WHERE date < ?")
            params.append(date)
        elif date_selector == 'After':
            query += ("SELECT * FROM Posts WHERE date > ?")
            params.append(date)
        print(query)

        if tags is not None:
            query += ("AND tags = ?")
            params.append(tags)

        result = cur.fetchall()



    return render_template('search.html', form=form)

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
