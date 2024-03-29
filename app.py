from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_login import current_user, login_required, LoginManager, UserMixin, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import logging
from markupsafe import escape
import atexit
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

logging.basicConfig(level=logging.DEBUG)

# Add Flask-Migrate configuration
migrate = Migrate(app, db)

# Set session lifetime to 10 minutes (auto-logout in case of inactivity)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

@app.before_request
def before_request():
    last_activity = session.get('last_activity')

    if last_activity is not None:
        # Convert datetime.utcnow() to a timezone-aware datetime object
        utc_now = datetime.now(pytz.utc)

        if last_activity < (utc_now - app.permanent_session_lifetime):
            # Session has timed out due to inactivity
            session.clear()
            flash('Your session has timed out due to inactivity. Please log in again.', 'info')
            return redirect(url_for('timeout_page'))

    # Update the last activity time for the current session
    session['last_activity'] = datetime.utcnow()

# Route for the custom timeout page
@app.route('/timeout')
def timeout_page():
    return render_template('timeout.html')  # Render your custom timeout page template

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # New field for admin status
    tickets = db.relationship('Ticket', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    theater = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    best_method = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.Integer, nullable=False)
    technology = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='unassigned')  # New field for status
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Ticket('{self.username}', '{self.technology}', '{self.updated_at}')"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_authenticated(self):
        # This property is required by Flask-Login to determine if the user is authenticated
        return True

    @property
    def is_active(self):
        # This property is required by Flask-Login to determine if the user is active
        return True

    @property
    def is_anonymous(self):
        # This property is required by Flask-Login to determine if the user is anonymous
        return False

    def get_id(self):
        # This method is required by Flask-Login to get the unique identifier for the user
        return str(self.id)

# Create the application context
app.app_context().push()

db.create_all()

@atexit.register
def shutdown_session():
    session.clear()  # Clear session data on server shutdown

@login_manager.user_loader
def load_user(user_id):
    print(f"load_user called with user_id: {user_id}")
    if user_id:
        user = User.query.get(int(user_id))
        print(f"Returning user: {user}")
        return user
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_admin:
            return f(*args, **kwargs)
        else:
            flash("You do not have permission to access this page.", 'error')
            return redirect(url_for('home'))
    return decorated_function

def camel_to_title_case(s):
    return ''.join([' ' + c.lower() if c.isupper() else c for c in s]).strip().title()

app.jinja_env.filters['camel_to_title_case'] = camel_to_title_case

def is_strong_password(password):
    return (
        len(password) >= 8 and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password) and
        any(char in '!@#$%^&*()-_=+[]{}|;:\'",.<>?/~`' for char in password)
    )

def is_strong_username(username):
    return len(username) >= 8


@app.route("/admin/admin_login_confirmation")
def admin_login_confirmation():
    return render_template("admin/admin_login_confirmation.html")

# Route for admin-only page
@app.route("/admin/admin_dashboard")
@login_required
@admin_required
def admin_dashboard():
    # Query the database to get the ticket counts
    total_unassigned_tickets_count = Ticket.query.filter_by(status='unassigned').count()
    total_assigned_tickets_count = Ticket.query.filter_by(status='assigned').count()
    total_resolved_tickets_count = Ticket.query.filter_by(status='resolved').count()
    total_deleted_tickets_count = Ticket.query.filter_by(status='deleted').count()

    # Assuming 'updated_at' is a datetime field in your Ticket model
    total_last_week_tickets_count = Ticket.query.filter(Ticket.updated_at >= datetime.now() - timedelta(days=7)).count()
    total_this_month_tickets_count = Ticket.query.filter(Ticket.updated_at >= datetime.now() - timedelta(days=30)).count()
    total_this_year_tickets_count = Ticket.query.filter(Ticket.updated_at >= datetime.now() - timedelta(days=365)).count()

    # Pass these counts as context variables to the template
    return render_template('admin/admin_dashboard.html', 
                           total_unassigned_tickets_count=total_unassigned_tickets_count,
                           total_assigned_tickets_count=total_assigned_tickets_count,
                           total_resolved_tickets_count=total_resolved_tickets_count,
                           total_deleted_tickets_count=total_deleted_tickets_count,
                           total_last_week_tickets_count=total_last_week_tickets_count,
                           total_this_month_tickets_count=total_this_month_tickets_count,
                           total_this_year_tickets_count=total_this_year_tickets_count)

@app.route("/admin/admin_view_tickets")
@login_required
@admin_required  # Ensure only admin can access this route
def admin_view_tickets():
    # Retrieve all tickets from the database, ordered by creation date (most recent first)
    all_tickets = Ticket.query.order_by(Ticket.updated_at.desc()).all()
    return render_template('admin/admin_view_tickets.html', all_tickets=all_tickets)

@app.route("/admin/delete_ticket/<int:ticket_id>", methods=["POST"])
def delete_ticket(ticket_id):
    # Retrieve the ticket from the database
    ticket = Ticket.query.get_or_404(ticket_id)

    # Update the status of the ticket to "deleted"
    ticket.status = "deleted"
    
    # Commit the changes to the database
    db.session.commit()
    
    # Redirect to the confirmation page
    return redirect(url_for("admin_ticket_deleted", ticket_id=ticket.id))

@app.route("/admin/delete_ticket/<int:ticket_id>", methods=["GET"])
def confirm_delete_ticket(ticket_id):
    # Retrieve the ticket from the database
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Render the confirmation page
    return render_template("admin/admin_delete_ticket_confirmation.html", ticket=ticket)

@app.route("/admin/ticket_deleted/<int:ticket_id>")
def admin_ticket_deleted(ticket_id):
    # Fetch ticket details from the database using ticket_id
    ticket = Ticket.query.get_or_404(ticket_id)
    # Render the template for ticket deletion confirmation
    return render_template("admin/admin_ticket_deleted.html", ticket=ticket)

@app.route('/dashboard/ticket_created')
def ticket_created():
    return render_template('dashboard/ticket_created.html')

@app.route("/login_confirmation")
@login_required
def login_confirmation():
    print(f"current_user: {current_user}")
    print(f"current_user.is_authenticated: {current_user.is_authenticated}")

    if current_user.is_authenticated:
        return render_template("login_confirmation.html", username=current_user.username)
    else:
        flash("You are not logged in.", 'error')
        return redirect(url_for('login'))

@app.route("/registration_confirmation")
def registration_confirmation():
    # Your code here
    return render_template("registration_confirmation.html")

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

        # Check if the username meets the strength criteria
        if not is_strong_username(username):
            flash("Username must be at least 8 characters long.", 'error')
            return redirect(url_for('register'))

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
                session['username'] = username
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
@login_required
def logout():
    logout_user()  # Log out the user
    session.clear()  # Clear all session data
    flash("You have been logged out.", 'success')
    return redirect(url_for('logout_page'))

@app.route("/logout_page")
def logout_page():
    return render_template("logout_page.html")

from flask import redirect

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username exists in the database
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Authentication successful
            session['user_id'] = user.id  # Store user information in the session
            login_user(user)  # Explicitly log in the user
            flash("Login successful!", 'success')

            # Check if the user is an admin
            if user.is_admin:
                # Redirect to admin login confirmation page
                return redirect(url_for('admin_login_confirmation'))  # Route for admin login confirmation page

            # Redirect to the user-specific page
            return redirect(url_for('login_confirmation', username=username))

        # Authentication failed
        flash("Invalid credentials. Please try again.", 'error')

    # If it's a GET request or login is unsuccessful, render the login form
    return render_template("login.html")

@app.route('/dashboard/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        # Get form data
        full_name = request.form['fullName']
        department = request.form['department']
        theater = request.form['theater']
        country = request.form['country']
        phone_number = request.form['phoneNumber']
        email = request.form['email']
        best_method = request.form['bestMethod']
        severity = request.form['severity']
        technology = request.form['technology']
        description = request.form['description']

        # Create a new ticket with the current user's ID
        new_ticket = Ticket(
            full_name=full_name,
            username=current_user.username,  # Assuming your Ticket model has a 'username' column
            department=department,
            theater=theater,
            country=country,
            phone_number=phone_number,
            email=email,
            best_method=best_method,
            severity=severity,
            technology=technology,
            description=description,
            user_id=current_user.id  # Set the user_id field
        )

        # Add and commit the new ticket to the database
        db.session.add(new_ticket)
        db.session.commit()

        flash('Ticket created successfully!', 'success')
        return redirect(url_for('ticket_created'))

    return render_template('dashboard/create_ticket.html')

@app.route("/dashboard/view_tickets")
@login_required
def view_tickets():
    # Retrieve the user's tickets, excluding those with the status "deleted"
    user_tickets = Ticket.query.filter_by(user=current_user).filter(Ticket.status != 'deleted').order_by(Ticket.updated_at.desc()).all()
    return render_template('dashboard/view_tickets.html', user_tickets=user_tickets)    

@app.route("/dashboard/overview")
@login_required
def overview():
    # Query ticket statistics for the current user
    unassigned_tickets_count = Ticket.query.filter_by(user_id=current_user.id, status='unassigned').count()
    assigned_tickets_count = Ticket.query.filter_by(user_id=current_user.id, status='assigned').count()
    resolved_tickets_count = Ticket.query.filter_by(user_id=current_user.id, status='resolved').count()
    deleted_tickets_count = Ticket.query.filter_by(user_id=current_user.id, status='deleted').count()
    
    # Query for tickets updated in the last week, month, and year
    now = datetime.utcnow()
    last_week_tickets_count = Ticket.query.filter(
        Ticket.user_id == current_user.id,
        Ticket.updated_at >= now - timedelta(weeks=1)
    ).count()
    this_month_tickets_count = Ticket.query.filter(
        Ticket.user_id == current_user.id,
        Ticket.updated_at >= now - timedelta(days=now.day - 1)
    ).count()
    this_year_tickets_count = Ticket.query.filter(
        Ticket.user_id == current_user.id,
        Ticket.updated_at >= now.replace(month=1, day=1)
    ).count()

    return render_template(
        'dashboard/overview.html',
        unassigned_tickets_count=unassigned_tickets_count,
        assigned_tickets_count=assigned_tickets_count,
        resolved_tickets_count=resolved_tickets_count,
        deleted_tickets_count=deleted_tickets_count,
        last_week_tickets_count=last_week_tickets_count,
        this_month_tickets_count=this_month_tickets_count,
        this_year_tickets_count=this_year_tickets_count
    )

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for('overview'))

@app.route('/dashboard/edit_ticket/<ticket_id>', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    # Retrieve the ticket to be edited from the database
    ticket = Ticket.query.get(ticket_id)

    if not ticket:
        flash('Ticket not found!', 'error')
        return redirect(url_for('view_tickets'))

    if request.method == 'POST':
        # Update the ticket details based on the form data
        ticket.full_name = request.form['fullName']
        ticket.department = request.form['department']
        ticket.theater = request.form['theater']
        ticket.country = request.form['country']
        ticket.phone_number = request.form['phoneNumber']
        ticket.email = request.form['email']
        ticket.best_method = request.form['bestMethod']
        ticket.severity = request.form['severity']
        ticket.technology = request.form['technology']
        ticket.description = request.form['description']

        # Print or flash the country value for debugging
        print(f"Country value in POST request: {ticket.country}")
        flash(f"Country value in POST request: {ticket.country}", 'info')

        # Update the 'updated_at' timestamp
        ticket.updated_at = datetime.utcnow()

        # Commit the changes to the database
        db.session.commit()

        flash('Ticket updated successfully!', 'success')
        return redirect(url_for('edit_confirmation'))

    # Render the edit_ticket.html template with the ticket data
    return render_template('dashboard/edit_ticket.html', ticket=ticket)

@app.route('/dashboard/edit_confirmation')
@login_required
def edit_confirmation():
    return render_template('dashboard/edit_confirmation.html')

@app.route("/contact")
def contact():
    return render_template("contact.html")

# Run the app locally on localhost
if __name__ == "__main__":
    app.run(debug=True, port=8080)