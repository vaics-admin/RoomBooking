
###Room.py file
from venv import logger
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import psycopg2
import bcrypt
import jwt
import secrets
import datetime
from datetime import timedelta, timezone
import os
import random
import string
import requests
import urllib.parse
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
# Database connection details
# DATABASE = {
#     'dbname': 'backend',
#     'user': 'postgres',
#     'password': '12345',
#     'host': 'localhost',
#     'port': '5432'
# }

DATABASE = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}

# SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")

# Secret key for JWT
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)  # Generate a secret if none exists.
    print("Generated new JWT_SECRET:", JWT_SECRET)  # print so you can set it as an env variable.

app.config['SECRET_KEY'] = JWT_SECRET

# Microsoft Graph API credentials
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET")
MS_TENANT_ID = os.environ.get("MS_TENANT_ID")
MS_REDIRECT_URI = os.environ.get("MS_REDIRECT_URI")

# Store access token and email details globally (in production, use a proper token storage solution)
access_token = None
pending_emails = []

# Function to establish connection with PostgreSQL
def get_db_connection():
    conn = psycopg2.connect(**DATABASE)
    return conn

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

# Microsoft Graph API Authentication Routes
@app.route('/ms-login')
def ms_login():
    auth_url = f'https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/authorize?' + \
              urllib.parse.urlencode({
                  'client_id': MS_CLIENT_ID,
                  'response_type': 'code',
                  'redirect_uri': MS_REDIRECT_URI,
                  'response_mode': 'query',
                  'scope': 'openid profile Mail.Send',
                  'state': '12345'  # Random string for CSRF protection
              })
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')

    if code:
        token_url = f'https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token'

        data = {
            'client_id': MS_CLIENT_ID,
            'client_secret': MS_CLIENT_SECRET,
            'code': code,
            'redirect_uri': MS_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }

        try:
            # Request to get the access token
            response = requests.post(token_url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            token_response = response.json()

            global access_token
            access_token = token_response.get('access_token')
            refresh_token = token_response.get('refresh_token')

            if access_token:
                # Process any pending emails
                if pending_emails:
                    for email_details in pending_emails:
                        if email_details.get('is_html', False):
                            # Send HTML email
                            send_email_graph_html(
                                email_details['to_email'],
                                email_details['subject'],
                                email_details['html_body'],
                                email_details.get('plain_body')
                            )
                        else:
                            # Send plain text email
                            send_email_graph_html(
                                email_details['to_email'],
                                email_details['subject'],
                                email_details['body']
                            )
                    pending_emails.clear()
                    print(f"Processed {len(pending_emails)} pending emails after authentication")

                # Redirect to frontend success page
                return redirect(os.environ.get('FRONTEND_URL', 'https://roombookingfrontend.onrender.com') + '/auth-success')

            # Redirect to frontend with error
            return redirect(os.environ.get('FRONTEND_URL', 'https://roombookingfrontend.onrender.com') + '/auth-error')

        except requests.exceptions.RequestException as error:
            print(f"Error getting tokens: {error}")
            # Redirect to frontend with error
            return redirect(os.environ.get('FRONTEND_URL', 'https://roombookingfrontend.onrender.com') + '/auth-error')
    else:
        # Redirect to frontend with error
        return redirect(os.environ.get('FRONTEND_URL', 'https://roombookingfrontend.onrender.com') + '/auth-error')

@app.route('/auth-error')
def auth_error():
    return jsonify({'error': 'Authentication failed or was canceled'}), 400

def send_email_graph_html(to_email, subject, html_body, plain_body=None):
    """Function to send HTML email using Microsoft Graph API."""
    global access_token, pending_emails

    # If no access token, store email details for later and prompt authentication
    if not access_token:
        pending_emails.append({
            'to_email': to_email,
            'subject': subject,
            'html_body': html_body,
            'plain_body': plain_body,
            'is_html': True
        })
        print(f"No access token available. Email queued for later sending to {to_email}")
        return {'status': 'queued', 'message': 'Authentication required'}

    url = 'https://graph.microsoft.com/v1.0/me/sendMail'

    email_data = {
        'message': {
            'subject': subject,
            'body': {
                'contentType': 'HTML',
                'content': html_body,
            },
            'toRecipients': [
                {
                    'emailAddress': {
                        'address': to_email,
                    },
                },
            ],
        },
    }

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.post(url, json=email_data, headers=headers)
        response.raise_for_status()
        print(f'HTML email sent successfully to {to_email}!')
        return {'status': 'sent', 'message': 'Email sent successfully'}
    except requests.exceptions.HTTPError as error:
        # If unauthorized, clear token so we know to reauthenticate
        if response.status_code == 401:
            access_token = None
            pending_emails.append({
                'to_email': to_email,
                'subject': subject,
                'html_body': html_body,
                'plain_body': plain_body,
                'is_html': True
            })
            print(f"Unauthorized. Token expired. Email queued for later sending to {to_email}")
            return {'status': 'queued', 'message': 'Authentication required, token expired', 'requiresRefresh': True}
        print(f"Error sending email: {error}")
        return {'status': 'error', 'message': str(error)}
    except requests.exceptions.RequestException as error:
        print(f"Error sending email: {error}")
        return {'status': 'error', 'message': str(error)}

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('fullName')
    employee_id = data.get('employeeId')
    email = data.get('email')
    phone_number = data.get('phoneNumber')
    department = data.get('department')
    designation = data.get('designation')
    password = data.get('password')

    if not all([full_name, employee_id, email, password, phone_number, department, designation]):
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM employees_register WHERE employee_id = %s", (employee_id,))
        if cur.fetchone():
         return jsonify({'error': 'Employee ID already registered'}), 400

        # Insert new user
        cur.execute("INSERT INTO employees_register (full_name, employee_id, email, phone_number, department, designation, password) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (full_name, employee_id, email, phone_number, department, designation, hashed_password))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Registration successful'}), 201
    except psycopg2.Error as e:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({'error': str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    employee_id = data.get('employeeId')
    password = data.get('password')

    if not employee_id or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT employee_id, full_name, password, phone_number FROM employees_register WHERE employee_id = %s", (employee_id,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            stored_password = user[2]
            user_phone = user[3]

            # Convert memoryview to bytes
            stored_password_bytes = bytes(stored_password)

            if bcrypt.checkpw(password.encode('utf-8'), stored_password_bytes):
                token = jwt.encode({
                    'employee_id': user[0],
                    'full_name': user[1],
                    'exp': datetime.datetime.now(timezone.utc) + timedelta(hours=24)
                }, JWT_SECRET, algorithm='HS256')

                return jsonify({
                    'token': token,
                    'full_name': user[1],
                    'employeeId': user[0],
                    'phoneNumber': user_phone
                }), 200
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

        else:
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    otp = generate_otp()
    
    # Send OTP via Microsoft Graph API
    subject = "Password Reset OTP"
    body = f"Your OTP is: {otp}"
    result = send_email_graph_html(email, subject, body)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM otps WHERE email = %s", (email,))  # delete old otp
    cur.execute("INSERT INTO otps (email, otp) VALUES (%s, %s)", (email, otp))
    conn.commit()
    cur.close()
    conn.close()

    if result['status'] == 'queued':
        return jsonify({
            'message': 'OTP generated but requires authentication to send email',
            'requiresAuth': True
        }), 202
    elif result['status'] == 'sent':
        return jsonify({'message': 'OTP sent to your email'}), 200
    else:
        # Still store the OTP in case they check their email manually
        return jsonify({
            'message': 'Error sending email: ' + result['message'],
            'requiresAuth': True
        }), 202

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('newPassword')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM otps WHERE email = %s AND otp = %s AND created_at >= %s", 
                (email, otp, datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=10)))
    otp_record = cur.fetchone()

    if otp_record:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cur.execute("UPDATE employees_register SET password = %s WHERE email = %s", (hashed_password, email))
        cur.execute("DELETE FROM otps WHERE email = %s", (email,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Password reset successful'}), 200
    else:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid OTP or OTP expired'}), 400
    
def format_time(time_obj):
    """Converts datetime.time object to 12-hour format."""
    hours = time_obj.hour
    minutes = time_obj.minute
    period = 'PM' if hours >= 12 else 'AM'
    hours = hours % 12 or 12
    return f"{hours}:{minutes:02d} {period}"

def is_weekend(date_str):
    try:
        date_obj = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        return date_obj.weekday() in [5, 6]
    except ValueError:
        return False

def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        token = auth_header.split(' ')[1]
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

def send_booking_email(email, full_name, room, date, time_from, time_to, booked_by=None):
    """Function to send booking confirmation email using Microsoft Graph API."""
    subject = f"{room} Booking Confirmation"

    # Create HTML email body with styling
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Room Booking Confirmation</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .email-container {{
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                background-color: #4a86e8;
                color: white;
                padding: 20px;
                text-align: center;
            }}
            .content {{
                padding: 20px;
                background-color: #ffffff;
            }}
            .booking-details {{
                background-color: #f5f5f5;
                border-radius: 6px;
                padding: 15px 20px;
                margin: 15px 0;
            }}
            .booking-item {{
                margin: 10px 0;
            }}
            .booking-label {{
                font-weight: bold;
                color: #555555;
            }}
            .footer {{
                text-align: center;
                padding: 15px;
                font-size: 14px
                color: #777777;
                background-color: #f9f9f9;
                border-top: 1px solid #e0e0e0;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <h2>Room Booking Confirmation</h2>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>Your room booking has been confirmed.</p>
                
                <div class="booking-details">
                    <div class="booking-item">
                        <span class="booking-label">Booked by:</span> {full_name}
                    </div>
                    <div class="booking-item">
                        <span class="booking-label">Room:</span> {room}
                    </div>
                    <div class="booking-item">
                        <span class="booking-label">Date:</span> {date}
                    </div>
                    <div class="booking-item">
                        <span class="booking-label">Time:</span> {time_from} to {time_to}
                    </div>
    """

    if booked_by:
        html_body += f"""
                    <div class="booking-item">
                        <span class="booking-label">Booked for:</span> {email}
                    </div>
        """

    html_body += """
                </div>
                
                <p>Thank you.</p>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Create a plain text version as fallback
    plain_body = f"""
    Hello,

    Your room booking has been confirmed.

    Details:
    - Booked by: {full_name}
    - Room: {room}
    - Date: {date}
    - Time: {time_from} to {time_to}
    """

    if booked_by:
        plain_body += f"\n- Booked for: {email}"

    plain_body += "\n\nThank you."

    # Update the send_email_graph function to handle HTML emails
    return send_email_graph_html(email, subject, html_body, plain_body)

@app.route('/book_room', methods=['POST'])
@token_required
def book_room():
    data = request.get_json()
    print(data)

    required_fields = ['fullName', 'employeeId', 'location', 'branch', 'room', 'date', 'timeFrom', 'timeTo', 'bookingType']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    full_name = data['fullName']
    employee_id = data['employeeId']
    location = data['location']
    branch = data['branch']
    room = data['room']
    date = data['date']
    time_from = data['timeFrom']
    time_to = data['timeTo']
    booking_type = data['bookingType']
    booked_for = data.get('bookedFor', '')

    try:
        date_format = "%Y-%m-%d %H:%M"
        start_datetime = datetime.datetime.strptime(f"{date} {time_from}", date_format)
        end_datetime = datetime.datetime.strptime(f"{date} {time_to}", date_format)

        if end_datetime <= start_datetime:
            return jsonify({"error": "End time must be later than start time."}), 400

        if start_datetime.date() != end_datetime.date():
            return jsonify({"error": "Booking cannot extend to the next day."}), 400

        if is_weekend(date) and not data.get('confirmWeekend', True):
            return jsonify({"error": "Booking is on a weekend. Please confirm."}), 400

    except ValueError:
        return jsonify({'error': 'Invalid time format'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Check for conflicting bookings
    cur.execute("""
        SELECT time_from, time_to FROM room_bookings
        WHERE room = %s AND date = %s
        AND NOT (time_to <= %s OR time_from >= %s)
    """, (room, date, time_from, time_to))

    conflicting_slots = cur.fetchall()

    if conflicting_slots:
        conflicts = [{'start': format_time(start), 'end': format_time(end)} for start, end in conflicting_slots]
        cur.close()
        conn.close()
        return jsonify({'error': 'Slot already booked. Please choose a different time.', 'conflicts': conflicts}), 400

    # Insert the booking into the database
    cur.execute("""
        INSERT INTO room_bookings (full_name, employee_id, location, branch, room, date, time_from, time_to, booking_type, booked_for)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (full_name, employee_id, location, branch, room, date, time_from, time_to, booking_type, booked_for))

    result = cur.fetchone()
    if result:
        booking_id = result[0]
        conn.commit()
    else:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({'error': 'Failed to insert booking'}), 500

    # Get registered user email
    cur.execute("SELECT email FROM employees_register WHERE employee_id = %s", (employee_id,))
    user_email = cur.fetchone()
    if user_email:
        send_booking_email(user_email[0], full_name, room, date, time_from, time_to)  # Send email to booker

    # If booked for someone else, send them an email too
    if booked_for and '@' in booked_for:
        send_booking_email(booked_for, full_name, room, date, time_from, time_to, booked_by=full_name)

    cur.close()
    conn.close()

    # check if email is queued
    global pending_emails

    if pending_emails:
        return jsonify({'message': 'Room booked successfully!', 'emailQueued': True}), 200

    return jsonify({'message': 'Room booked successfully!'}), 200

# -------------------- EMAIL AUTOCOMPLETE ROUTES --------------------

@app.route('/get_employee_emails', methods=['GET'])
def get_employee_emails():
    search_term = request.args.get('search', '')

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if search_term:
            cur.execute("SELECT email FROM employees WHERE email ILIKE %s LIMIT 10", (f'%{search_term}%',))
        else:
            cur.execute("SELECT email FROM employees LIMIT 10")

        emails = [row[0] for row in cur.fetchall()]

        cur.close()
        conn.close()

        return jsonify({'emails': emails}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/store_email', methods=['POST'])
def store_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM employees WHERE email = %s", (email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO employees (email) VALUES (%s)", (email,))
            conn.commit()

        cur.close()
        conn.close()

        return jsonify({'message': 'Email stored successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to check authentication status
@app.route('/auth-status', methods=['GET'])
def auth_status():
    global access_token
    
    if access_token:
        return jsonify({
            'authenticated': True,
            'pendingEmails': len(pending_emails)
        }), 200
    else:
        return jsonify({
            'authenticated': False,
            'pendingEmails': len(pending_emails)
        }), 200

## Route to refresh the access token using a refresh token
@app.route('/refresh-token', methods=['POST'])
def refresh_token():
    refresh_token = request.json.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'No refresh token provided'}), 400
    
    token_url = f'https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token'
    
    data = {
        'client_id': MS_CLIENT_ID,
        'client_secret': MS_CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
        'scope': 'openid profile Mail.Send'
    }
    
    try:
        response = requests.post(token_url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        token_response = response.json()
        
        global access_token
        access_token = token_response.get('access_token')
        new_refresh_token = token_response.get('refresh_token')
        
        if access_token:
            return jsonify({
                'success': True,
                'refresh_token': new_refresh_token
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to refresh token'
            }), 400
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True)