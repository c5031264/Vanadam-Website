# This code imports the Flask library and some functions from it.
from flask import Flask, render_template
import sqlite3

try:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
except:
    print("Error connecting to database")


# Create a Flask application instance
app = Flask(__name__)

# Routes
#===================
# These define which template is loaded, or action is taken, depending on the URL requested
#===================
# Home Page
@app.route('/')
def index():
    return render_template('home.html', title="Vanadam Halo")

@app.route('/mapPage/<mapName>', methods=['GET'])
def mapPage(mapName):
    print(f'got request for: {mapName}')
    return render_template(f'{mapName}.html', mapName=mapName)

@app.route('login', methods=['GET'])
def login():
    pass

@app.route('/logout')
def logout():
    pass

@app.route('/register', methods=['GET', 'POST'])
def register():
    pass

@app.route('/report', methods=['POST'])
def report():
    pass

# Run application
#=========================================================
# This code executes when the script is run directly.
if __name__ == '__main__':
    print("Starting Flask application...")
    print("Open Your Application in Your Browser: http://localhost:81")
    # The app will run on port 81, accessible from any local IP address
    app.run(host='0.0.0.0', port=81)
