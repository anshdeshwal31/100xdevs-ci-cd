import os
from flask import Flask, request, session, redirect, url_for, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Initialize the Flask application
app = Flask(__name__)

# --- Configuration ---
# A SECRET_KEY is crucial for session management. It should be a long, random string.
# Always load from environment variables in production to prevent sensitive data exposure.
# OWASP A05: Security Misconfiguration - Ensure secrets are not hardcoded.
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a_very_secret_key_that_should_be_changed_in_production_12345')

# Configure secure session cookies
# OWASP A05: Security Misconfiguration - Set secure cookie attributes.
# SESSION_COOKIE_SECURE ensures cookies are only sent over HTTPS.
app.config['SESSION_COOKIE_SECURE'] = True
# SESSION_COOKIE_HTTPONLY prevents client-side JavaScript from accessing the session cookie,
# mitigating XSS attacks.
app.config['SESSION_COOKIE_HTTPONLY'] = True
# SESSION_COOKIE_SAMESITE='Lax' or 'Strict' helps mitigate CSRF attacks.
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# In-memory user storage (for demonstration purposes)
# In a real application, this would be a database (e.g., PostgreSQL, MySQL)
# with proper ORM (e.g., SQLAlchemy) and secure connection practices.
# Structure: {username: {'password_hash': 'hashed_password_string'}}
users = {}

# --- Authentication Decorator ---
def login_required(f):
    """
    Decorator to ensure a user is logged in before accessing a route.
    OWASP A01: Broken Access Control - Enforces authentication for protected resources.
    Returns a JSON error for unauthorized access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    """
    A simple root route to demonstrate navigation.
    """
    if 'username' in session:
        return f"Hello, {session['username']}! You are logged in. <a href='/logout'>Logout</a> | <a href='/protected'>Protected Resource</a>"
    return "Welcome! <a href='/register_page'>Register</a> | <a href='/login_page'>Login</a>"

@app.route('/register_page')
def register_page():
    """
    Simple page to display a registration form.
    """
    return render_template_string("""
        <h1>Register</h1>
        <form method="POST" action="/register">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Register">
        </form>
        <p>Already have an account? <a href="/login_page">Login here</a>.</p>
    """)

@app.route('/register', methods=['POST'])
def register():
    """
    Handles user registration.
    OWASP A07: Identification and Authentication Failures - Implements a secure registration process.
    OWASP A03: Injection - Includes server-side input validation.
    OWASP A02: Cryptographic Failures - Uses strong password hashing.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # --- Server-side Input Validation ---
    # Never trust user-provided data without validation.
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Basic length checks for username and password
    if len(username) < 3 or len(username) > 20:
        return jsonify({'message': 'Username must be between 3 and 20 characters'}), 400
    
    # Enforce a minimum password length and complexity for strong passwords.
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400
    if not any(char.isdigit() for char in password) or \
       not any(char.isupper() for char in password) or \
       not any(char.islower() for char in password):
        return jsonify({'message': 'Password must contain at least one digit, one uppercase, and one lowercase letter'}), 400

    if username in users:
        return jsonify({'message': 'Username already exists'}), 409 # Conflict status code
    
    # Hash the password before storing it.
    # OWASP A02: Cryptographic Failures - Use strong, modern hashing algorithms.
    # werkzeug.security uses PBKDF2 by default, which is a good choice.
    hashed_password = generate_password_hash(password)
    users[username] = {'password_hash': hashed_password}
    
    return jsonify({'message': 'User registered successfully'}), 201 # Created

@app.route('/login_page')
def login_page():
    """
    Simple page to display a login form.
    """
    return render_template_string("""
        <h1>Login</h1>
        <form method="POST" action="/login">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Login">
        </form>
        <p>Don't have an account? <a href="/register_page">Register here</a>.</p>
    """)

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login.
    OWASP A07: Identification and Authentication Failures - Implements a secure login process.
    OWASP A03: Injection - Includes server-side input validation.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # --- Server-side Input Validation ---
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = users.get(username)

    # OWASP A07: Avoid generic error messages to prevent username enumeration.
    # In a real-world scenario, to prevent timing attacks, `check_password_hash`
    # should ideally be called even if the user doesn't exist, and the response
    # time should be consistent. For simplicity in this example, we check user existence first.
    if user and check_password_hash(user['password_hash'], password):
        session['username'] = username
        # Flask's session management implicitly handles session ID regeneration
        # when a new session is created, which helps prevent Session Fixation attacks.
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        # Generic error message for both invalid username and password
        return jsonify({'message': 'Invalid username or password'}), 401 # Unauthorized

@app.route('/logout')
@login_required # Good practice to ensure only logged-in users can explicitly logout.
def logout():
    """
    Handles user logout.
    OWASP A07: Identification and Authentication Failures - Implements a proper logout process.
    """
    session.pop('username', None) # Remove username from session to log out the user.
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/protected')
@login_required # This route requires authentication, enforced by the decorator.
def protected_resource():
    """
    A route that can only be accessed by authenticated users.
    OWASP A01: Broken Access Control - Access is restricted to authenticated users.
    """
    return jsonify({'message': f'Hello {session["username"]}, this is a protected resource!'}), 200

# --- Run the application ---
if __name__ == '__main__':
    # In a production environment, you would use a WSGI server like Gunicorn or uWSGI.
    # debug=True should NEVER be used in production as it exposes sensitive information
    # and allows arbitrary code execution.
    # host='0.0.0.0' makes the server accessible from any IP, useful for Docker/VMs.
    # Ensure HTTPS is enforced in production (e.g., via a reverse proxy like Nginx).
    app.run(debug=True, host='0.0.0.0', port=5000)