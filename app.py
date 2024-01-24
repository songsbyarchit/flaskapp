from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

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
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def current_user(self):
        # Check if the user is in the session or has other indicators of being logged in
        return 'user_id' in session  # Assuming you store user_id in the session upon login

# Create the application context
app.app_context().push()

# Create the database and tables
# db.create_all()

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

@app.route("/registration_confirmation")
def registration_confirmation():
    # Your code here
    return render_template("registration_confirmation.html")

@app.route("/login_confirmation")
def login_confirmation():
    return render_template("login_confirmation.html")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        registration_successful = False
        username_exists = False
        email_exists = False
        password_valid = True
        password_match = True

        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if the username already exists in the database
        existing_username = User.query.filter_by(username=username).first()

        if existing_username:
            username_exists = True
            flash("This username already exists. Please choose a different username.", 'error')

        # Check if the email already exists in the database
        existing_email = User.query.filter_by(email=email).first()

        if existing_email:
            email_exists = True
            flash("There is already an account associated with this email.", 'error')

        # Validate password
        if not is_strong_password(password):
            password_valid = False
            flash("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.", 'error')

        # Check if password matches confirm password
        if password != confirm_password:
            password_match = False
            flash("Password and Confirm Password do not match.", 'error')

        # Continue with registration if username and email are not duplicates,
        # password is valid, and passwords match
        if not username_exists and not email_exists and password_valid and password_match:
            new_user = User(username=username, email=email)
            new_user.set_password(password)  # Set the password using the hash

            try:
                db.session.add(new_user)
                db.session.commit()
                registration_successful = True
                flash("Registration successful. You can now login.", 'success')
                return redirect(url_for('registration_confirmation', username=username))
            
            except IntegrityError as e:
                # Handle other IntegrityError scenarios, if any
                db.session.rollback()

        # Render the registration form with error messages
        return render_template("register.html", registration_successful=registration_successful,
                               username_exists=username_exists, email_exists=email_exists,
                               password_valid=password_valid, password_match=password_match)

    # If it's a GET request, render the registration form
    return render_template("register.html")

@app.route("/logout", methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", 'success')
    return redirect(url_for('logout_page'))

@app.route("/logout_page")
def logout_page():
    return render_template("logout.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_successful = False

        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username exists in the database
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Authentication successful
            login_successful = True
            session['user_id'] = user.id  # Store user information in the session

        else:
            # Authentication failed
            flash("Invalid username or password. Please try again.", 'error')

        # Handle the outcome (e.g., redirect to a different page on successful login)
        if login_successful:
            # Redirect to a logged-in area or display a confirmation message
            return redirect(url_for('login_confirmation', username=username))

    # If it's a GET request or login is unsuccessful, render the login form
    return render_template("login.html")

@app.route("/dashboard/create_ticket")
def create_ticket():
    return render_template("dashboard/create_ticket.html")

@app.route("/dashboard/view_tickets")
def view_tickets():
    return render_template("dashboard/view_tickets.html")

@app.route("/dashboard/overview")
def overview():
    return render_template("dashboard/overview.html")

@app.route("/dashboard/faq")
def faq():
    return render_template("dashboard/faq.html")

# Run the app locally on localhost
if __name__ == "__main__":
    app.run(debug=True, port=5001)  # Set debug to True for development purposes