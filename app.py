from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
import re
from datetime import datetime, timedelta
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
from flask import Flask, request, render_template, redirect, url_for, flash, session
from datetime import datetime
import mysql.connector
from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password are required")
            return render_template('login.html')

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            user_id = user['user_id']
            ip = request.remote_addr
            now = datetime.now()

            cursor.execute("""
                SELECT login_time FROM user_login_history
                WHERE user_id = %s
                ORDER BY login_time DESC
            """, (user_id,))
            rows = cursor.fetchall()

            fail_count = 0
            for row in rows:
                login_time = row['login_time']
                if (now - login_time).total_seconds() <= 120:
                    fail_count += 1
                else:
                    break 

            if fail_count >= 5:
                flash("Too many failed login attempts. Please wait 1 minute before trying again.")
                return render_template('wait.html')

          
            if check_password_hash(user['password_hash'], password):
                session['user_id'] = user_id
                cursor.execute("""INSERT INTO user_login_history (user_id, ip_address,success) VALUES (%s, %s,1)  """, (user_id, ip))
                flash("Login successful!")
                return redirect(url_for('dashboard'))
            else:
           
                cursor.execute("""
                    INSERT INTO user_login_history (user_id, ip_address)
                    VALUES (%s, %s)
                """, (user_id, ip))
                db.commit()
                flash("Incorrect password.")
                return render_template('login.html')
        else:
            flash("User not found.")
            return render_template('login.html')

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
@app.route('/wait')
def wait():
    
    return render_template('wait.html')
# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out")
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)



# blacklisted ip block in login and geolocation tag leeft ################################