from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from flask import redirect, url_for

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Add Flask-Migrate configuration
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Create the application context
app.app_context().push()

# Create the database and tables
db.create_all()

def is_strong_password(password):
    # Add your criteria for a strong password here
    # For example, at least 8 characters, uppercase, lowercase, digit, and special character
    return (
        len(password) >= 8 and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password) and
        any(char in '!@#$%^&*()-_=+[]{}|;:\'",.<>?/~`' for char in password)
    )

@app.route("/login_confirmation")
def login_confirmation():
    return render_template("login_confirmation.html", username="JohnDoe")  # Replace "JohnDoe" with the actual username

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        registration_successful = False
        email_exists = False
        password_valid = True
        password_match = True

        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            email_exists = True

        # Validate password
        if not is_strong_password(password):
            password_valid = False
            flash("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.", 'error')

        # Check if password matches confirm password
        if password != confirm_password:
            password_match = False
            flash("Password and Confirm Password do not match.", 'error')

        # Continue with registration if email is not duplicate, password is valid, and passwords match
        if not email_exists and password_valid and password_match:
            new_user = User(username=username, email=email, password=password)

            try:
                db.session.add(new_user)
                db.session.commit()
                registration_successful = True
            except IntegrityError as e:
                # Handle other IntegrityError scenarios, if any
                db.session.rollback()

        return render_template("register.html", registration_successful=registration_successful, email_exists=email_exists, password_valid=password_valid, password_match=password_match)

    # If it's a GET request, render the registration form
    return render_template("register.html")

@app.route("/login")
def login():
    return render_template("login.html")

# Run the app locally on localhost
if __name__ == "__main__":
    app.run(debug=True, port=8080)  # Set debug to True for development purposes