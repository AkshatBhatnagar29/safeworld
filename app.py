from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)
cursor = db.cursor(dictionary=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("User already exists. Please log in.")
            return redirect('/login')
        
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        db.commit()
        flash("User created successfully. Please log in.")
        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        # Check if the entered password matches the stored password hash
        if check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']  # Store user ID in session
            flash("Login successful!")
            return render_template('dashboard.html', email=email)
        else:
            flash("Incorrect password.")
            return redirect('/login')
    else:
        flash("User not found. Please sign up.")
        return redirect('/signup')

if __name__ == '__main__':
    app.run(debug=True)
