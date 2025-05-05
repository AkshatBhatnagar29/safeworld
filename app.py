from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash,abort
import mysql.connector
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
import requests
import pandas as pd
from datetime import datetime, timedelta
import ipaddress
import re
import random
import hashlib, random

def generate_transaction_id():
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:10]

load_dotenv()
api_key = os.environ.get("IPINFO_API_KEY")
app = Flask(__name__)
CORS(app)  
app.secret_key = os.getenv("FLASK_SECRET_KEY", "9281fb58a564037c0b3040c4f20250b0")

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")  
    )
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/')
def home():
    return render_template('index.html')




@app.route('/signup', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print(request.form)  
        
        f_name = request.form.get('f_name', '')
        m_name = request.form.get('m_name', '')
        l_name = request.form.get('l_name', '')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        
        if not email or not phone_number or not password:
            flash("Email, phone number, and password are required")
            return render_template('signup.html', form_data=request.form)
        
        phone_number = re.sub(r'[^0-9]', '', phone_number)
        
        
        if len(phone_number) > 15:
            flash("Phone number is too long. Maximum 15 digits allowed.")
            return render_template('signup.html', form_data=request.form)
        
        hashed_password = generate_password_hash(password)
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        try:
            print("Checking if user exists...")
            cursor.execute("SELECT * FROM users WHERE email = %s OR phone_number = %s", (email, phone_number))
            existing_user = cursor.fetchone()
            print(f"User exists: {existing_user is not None}")
            
            if existing_user:
                flash("User already exists. Please log in.")
                cursor.close()
                db.close()
                return render_template('signup.html', form_data=request.form)
            
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
    
    return render_template('signup.html')

def get_ipinfo_location(ip):
    try:
        api_key = "517e0433ce08fb"  
        res = requests.get(f"https://ipinfo.io/{ip}/json?token={api_key}")
        print(f"Requesting IPinfo for IP: {ip}")  
        if res.status_code == 200:
            data = res.json()
            print("IPinfo data:", data)
            return data.get("city", ""), data.get("country", "")
        else:
            print("IPinfo error:", res.status_code, res.text)
            return "", ""
    except Exception as e:
        print("IPinfo lookup failed:", e)
        return "", ""

def get_location_from_form_or_ip():
    location = ''
    user_ip = request.remote_addr  
    city, country = get_ipinfo_location(user_ip)
    if city or country:
        location = f"{city}, {country}"
    else:
        location = "Unknown Location"  
    print(f"Location: {location}")
    return location


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

        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

        
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return render_template('wait.html')

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        city, country = get_ipinfo_location(ip)

        if user:
            user_id = user['user_id']
            now = datetime.now()

            cursor.execute("""
                SELECT city, country FROM user_login_history 
                WHERE user_id = %s AND success = 1 AND login_time >= NOW() - INTERVAL 5 MINUTE 
                ORDER BY login_time DESC LIMIT 1
            """, (user_id,))
            recent_login = cursor.fetchone()

            if recent_login:
                if recent_login['city'] != city or recent_login['country'] != country:
                    flash("Suspicious login: You're logging in from a new location within 5 minutes. Try again later.")
                    return render_template('block.html')

            cursor.execute("SELECT * FROM blacklisted_ip WHERE ip_address = %s", (ip,))
            blacklist = cursor.fetchone()
            if blacklist:
                flash("Your IP address is blacklisted. Please contact support.")
                return render_template('block.html')

            cursor.execute("""
                SELECT login_time FROM user_login_history
                WHERE user_id = %s AND success = 0
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
                print("Session user_id set to:", session.get('user_id'))  
                su = 1
                cursor.execute("""
                    INSERT INTO user_login_history (user_id, ip_address, city, country, success) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, ip, city, country, su))
                db.commit()
                flash("Login successful!")
                return redirect(url_for('dashboard'))
            else:
                cursor.execute("""
                    INSERT INTO user_login_history (user_id, ip_address, success) 
                    VALUES (%s, %s, 0)
                """, (user_id, ip))
                db.commit()
                flash("Incorrect password.")
                return render_template('login.html')
        else:
            flash("User not found.")
            return render_template('login.html')

        cursor.close()
        db.close()

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    logger.debug("Accessing dashboard for user_id: %s", session.get('user_id'))
    if 'user_id' not in session:
        flash("Please log in to access your dashboard")
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id, f_name, m_name, l_name, email, phone_number, User_Balance FROM users WHERE user_id = %s", (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            session.clear()
            flash("User not found")
            return redirect(url_for('login'))
        logger.debug("User data: %s", user)
        return render_template('dashboard.html', user=user)
    except mysql.connector.Error as err:
        logger.error("Database error in dashboard: %s", err)
        flash(f"Database Error: {err}")
        return redirect(url_for('login'))
    finally:
        cursor.close()
        db.close()
    print("Accessing dashboard, session user_id:", session.get('user_id'))

@app.route('/add_money', methods=['GET', 'POST'])
def add_money():
    if 'user_id' not in session:
        flash("Please log in to add money")
        return redirect(url_for('login'))
    
    # Debug - Check if user_id is properly set
    print(f"Session user_id: {session.get('user_id')}")
    
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', 0))
            if amount <= 0:
                flash("Amount must be greater than 0", "error")
                return redirect(url_for('add_money'))
            
            db = get_db_connection()
            cursor = db.cursor()
            
            # First check if the user exists
            cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (session['user_id'],))
            user = cursor.fetchone()
            if not user:
                flash("User not found", "error")
                return redirect(url_for('add_money'))
            
            # Debug - Print before balance
            cursor.execute("SELECT User_Balance FROM users WHERE user_id = %s", (session['user_id'],))
            before_balance = cursor.fetchone()[0]
            print(f"Before update: User {session['user_id']} balance = {before_balance}")
            
            # Update the balance
            cursor.execute("UPDATE users SET User_Balance = User_Balance + %s WHERE user_id = %s", 
                          (amount, session['user_id']))
            
            # Check if any rows were affected
            rows_affected = cursor.rowcount
            print(f"Rows affected by UPDATE: {rows_affected}")
            
            if rows_affected == 0:
                db.rollback()
                flash("Failed to update balance: No rows affected", "error")
                return redirect(url_for('add_money'))
                
            # Debug - Print after balance
            cursor.execute("SELECT User_Balance FROM users WHERE user_id = %s", (session['user_id'],))
            after_balance = cursor.fetchone()[0]
            print(f"After update: User {session['user_id']} balance = {after_balance}")
            
            txn_id = generate_transaction_id()
            cursor.execute("""
                  INSERT INTO transaction_table (transaction_id, sender_id, receiver_id, amount, transaction_type, time, ip_address_sender)
                    VALUES (%s, %s, %s, %s, 'add_money', NOW(), %s)
            """, (txn_id, session['user_id'], session['user_id'], amount, request.remote_addr))
            
            # Explicitly commit the transaction
            db.commit()
            print("Transaction committed successfully")
            
            flash(f"₹{amount:.2f} added successfully!", "message")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.rollback()
            print(f"Exception in add_money: {e}")
            flash(f"Failed to add money: {e}", "error")
        finally:
            cursor.close()
            db.close()
    
    return render_template('add_money.html')



def process_transaction(sender_id, receiver_id, amount, transaction_type, sender_ip, receiver_ip, location):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT User_Balance FROM users WHERE user_id = %s", (sender_id,))
        row = cursor.fetchone()
        if not row:
            return "Sender not found"
        if amount > float(row['User_Balance']):
            return "Transaction Failed: Insufficient balance"

       
        transaction_id = str(uuid.uuid4()).replace('-', '')[:10]

        cursor.execute(
            "INSERT INTO transaction_table (transaction_id, sender_id, receiver_id, amount, transaction_type, time, ip_address_sender, ip_address_receiver, location) "
            "VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s, %s)",
            (transaction_id, sender_id, receiver_id, amount, transaction_type, sender_ip, receiver_ip, location)
        )
        cursor.execute(
            "UPDATE users SET User_Balance = User_Balance - %s WHERE user_id = %s",
            (amount, sender_id)
        )
        cursor.execute(
            "UPDATE users SET User_Balance = User_Balance + %s WHERE user_id = %s",
            (amount, receiver_id)
        )
        db.commit()

   
        cursor.execute(
            "SELECT amount FROM transaction_table WHERE sender_id = %s ORDER BY time DESC LIMIT 30;",
            (sender_id,)
        )
        amounts = [float(r['amount']) for r in cursor.fetchall()]

       
        if len(amounts) >= 5:
            series = pd.Series(amounts)
            q1, q3 = series.quantile([0.25, 0.75])
            iqr = q3 - q1
            upper = q3 + 1.5 * iqr
            if amount > upper:
                fraud_transaction_id = str(uuid.uuid4()).replace('-', '')[:10]
                
                cursor.execute(
                    "INSERT INTO transaction_table (transaction_id, sender_id, receiver_id, amount, transaction_type, time, ip_address_sender, ip_address_receiver, location) "
                    "VALUES (%s, %s, %s, %s, 'fraud', NOW(), %s, %s, %s)",
                    (fraud_transaction_id, sender_id, receiver_id, amount, sender_ip, receiver_ip, location)
                )
                cursor.execute(
                    "INSERT INTO fraud_report (report_id, transaction_id, report_details, report_status, reported_at) "
                    "VALUES (CONCAT(SUBSTRING(MD5(RAND()), 1, 5)), %s, %s, 'Pending', NOW());",
                    (transaction_id, f"Outlier transaction ₹{amount} by user {sender_id}")
                )
                cursor.execute(
                    "INSERT IGNORE INTO blacklisted_ip (ip_address, reason, blocked_At) "
                    "VALUES (%s, %s, NOW());",
                    (sender_ip, "Outlier transaction")
                )
                db.commit()
                return "Transaction Blocked: Outlier detected"
                return redirect(url_for('dashboard'))
        return "Transaction Successful"

    except Exception as e:
        db.rollback()
        return f"Transaction Failed: {str(e)}"
    finally:
        cursor.close()
        db.close()
@app.route('/pro_transaction', methods=['GET', 'POST'])
def transaction_page():
    db=get_db_connection()
    

    cursor = db.cursor(dictionary=True)
    if 'user_id' not in session:
        flash("Please log in to access the transaction page")
        return redirect(url_for('login'))

    message = None

    if request.method == 'POST':
        sender_id = session['user_id']
        receiver_id = request.form.get('receiver_id')
        amount = float(request.form.get('amount', 0))
        ttype = request.form.get('transaction_type', 'transfer')
        sender_ip = request.remote_addr
        cursor.execute("SELECT ip_address FROM user_login_history WHERE user_id = %s ORDER BY login_time DESC LIMIT 1", (receiver_id,))
        receiver_ip_row = cursor.fetchone()
        receiver_ip = receiver_ip_row['ip_address'] if receiver_ip_row else 'N/A'

        location = get_location_from_form_or_ip()

        message = process_transaction(
            sender_id, receiver_id, amount, ttype,
            sender_ip, receiver_ip,location
        )
        if "Success" in message:
            flash("Transaction Successful!")
            return redirect('/dashboard')  
        else:
            return render_template('pro_transaction.html', message=message)
    db.commit()
    cursor.close(); db.close()
    return render_template('pro_transaction.html', message=message)

@app.route('/transactions')
def view_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM transaction_table WHERE sender_id = %s ORDER BY time DESC;",
        (session['user_id'],)
    )
    transactions = cursor.fetchall()
    cursor.close(); db.close()

    return render_template('transactions.html', transactions=transactions)

@app.route('/fraud_transactions')
def fraud_transactions():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT fr.* 
        FROM fraud_report fr
        JOIN transaction_table t ON fr.transaction_id = t.transaction_id
        WHERE t.sender_id = %s
    """, (user_id,))
    frauds = cur.fetchall()
    cur.close()

    return render_template('fraud_transactions.html', frauds=frauds)



@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out")
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)

# location based blocking and location left blank