from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
import re

load_dotenv()

app = Flask(__name__)
CORS(app)  # Added to enable Cross-Origin support
app.secret_key = os.getenv("FLASK_SECRET_KEY", "9281fb58a564037c0b3040c4f20250b0")

# Database connection function - creates a new connection for each request
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Signup Route (fixed duplicate decorators)
@app.route('/signup', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print(request.form)  # Debug print to see form data
        
        # Safely get all form values
        f_name = request.form.get('f_name', '')
        m_name = request.form.get('m_name', '')
        l_name = request.form.get('l_name', '')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        
        # Validate required fields
        if not email or not phone_number or not password:
            flash("Email, phone number, and password are required")
            return render_template('signup.html', form_data=request.form)
        
        # Clean phone number - remove spaces and non-numeric characters
        phone_number = re.sub(r'[^0-9]', '', phone_number)
        
        # Check if phone number is too long for database
        if len(phone_number) > 15:
            flash("Phone number is too long. Maximum 15 digits allowed.")
            return render_template('signup.html', form_data=request.form)
        
        # Hash password
        hashed_password = generate_password_hash(password)
        
        # Get fresh database connection
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        try:
            # Check if user exists
            print("Checking if user exists...")
            cursor.execute("SELECT * FROM users WHERE email = %s OR phone_number = %s", (email, phone_number))
            existing_user = cursor.fetchone()
            print(f"User exists: {existing_user is not None}")
            
            if existing_user:
                flash("User already exists. Please log in.")
                cursor.close()
                db.close()
                return render_template('signup.html', form_data=request.form)
            
            # Insert new user
            print("Attempting to insert user...")
            cursor.execute("""
                INSERT INTO users (f_name, m_name, l_name, email, phone_number, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (f_name or None, m_name or None, l_name or None, email, phone_number, hashed_password))
            
            db.commit()
            print("User successfully added to database")
            flash("Signup successful! Please log in.")
            cursor.close()
            db.close()
            return redirect(url_for('login'))
            
        except mysql.connector.Error as err:
            db.rollback()
            print(f"Database Error: {err}")
            flash(f"Database Error: {err}")
            cursor.close()
            db.close()
            return render_template('signup.html', form_data=request.form)
    
    # GET request - show empty form
    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash("Email and password are required")
            return render_template('login.html')
        
        # Get fresh database connection
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if user:
            if check_password_hash(user['password_hash'], password):
                session['user_id'] = user['user_id']
                flash("Login successful!")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password.")
                return render_template('login.html')
        else:
            flash("User not found. Please sign up.")
            return render_template('login.html')
    
    # GET request - show login form
    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard")
        return redirect(url_for('login'))
        
    # Get fresh database connection
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    cursor.close()
    db.close()
    
    if not user:
        session.clear()
        flash("User not found")
        return redirect(url_for('login'))
        
    return render_template ('index.html', user=user)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)