from flask import Flask, render_template, request, url_for, redirect, session
from pymongo import MongoClient
import bcrypt
import re

# Set app as a Flask instance
app = Flask(__name__)

# Encryption relies on secret keys so they could be run
app.secret_key = "testing"

# Connect to your MongoDB database
def MongoDB():
    """Connect to MongoDB Atlas and return the 'register' collection."""
    try:
        client = MongoClient("mongodb+srv://soudagarfaizan2:SpiderManIsCool1@cluster0.xjxkh.mongodb.net/")
        db = client.get_database('total_records')
        return db.register
    except Exception as e:
        print(f"Database connection failed: {e}")
        exit()

records = MongoDB()

# Password validation function
def validate_password(password):
    """Validate the user's password based on the following rules:
    - At least 8 characters long
    - Contains at least one lowercase letter
    - Contains at least one uppercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character."

    return "Valid password!"

# Assign URLs to have a particular route
@app.route("/", methods=['POST', 'GET'])
def index():
    message = ''
    if "email" in session:
        return redirect(url_for("logged_in"))
    
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        
        # Validate password before proceeding
        password_validation = validate_password(password1)
        if password_validation != "Valid password!":
            message = password_validation
            return render_template('index.html', message=message)
        
        # Check if user or email already exists in the database
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            # Hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            # Insert user data into the database
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            
            # Redirect to logged-in page
            return render_template('logged_in.html', email=email)
    
    return render_template('index.html')

@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))
    
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if email exists in the database
        email_found = records.find_one({"email": email})
        if email_found:
            passwordcheck = email_found['password']
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email
                return redirect(url_for('logged_in'))
            else:
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    
    return render_template('login.html', message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("login"))

@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
