from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from twilio.rest import Client
from functools import wraps
import random
from sqlalchemy.exc import IntegrityError

# App and database setup
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///donation.db"
app.config["SECRET_KEY"] = "e3d750993677abbc390b44a48b4e9e24"

# Mail configuration (update with your actual credentials)
app.config["MAIL_SERVER"] = "smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USERNAME"] = "your_mailtrap_username"
app.config["MAIL_PASSWORD"] = "your_mailtrap_password"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

# Initialize extensions
mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
scheduler = BackgroundScheduler()

# Twilio configuration (update with your actual credentials)
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
TWILIO_PHONE_NUMBER = 'your_twilio_phone_number'
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    location = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(120), nullable=False)
    birthday = db.Column(db.Date, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    pin = db.Column(db.String(6), nullable=True)  # Only super admin will have a PIN

# Donation model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(50), default='USD')
    user = db.relationship("User", backref="donations")

# Schedule for sending birthday emails
def send_birthday_emails():
    today = datetime.now().date()
    users_with_birthday = User.query.filter(
        db.extract('month', User.birthday) == today.month,
        db.extract('day', User.birthday) == today.day
    ).all()
    for user in users_with_birthday:
        msg = Message(
            "Happy Birthday!",
            sender="noreply@donationtracker.com",
            recipients=[user.email]
        )
        msg.body = f"Dear {user.name},\n\nHappy Birthday! We wish you a wonderful day!\n\nBest regards,\nDonation Tracker Team"
        mail.send(msg)

scheduler.add_job(send_birthday_emails, 'cron', day='*', hour=0)  # Runs every day at midnight
scheduler.start()

# Function to send bulk SMS
def send_bulk_sms(message):
    users = User.query.all()
    for user in users:
        client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=user.phone
        )

# Function to send bulk emails
def send_bulk_email(subject, body):
    users = User.query.all()
    for user in users:
        msg = Message(subject, sender="noreply@donationtracker.com", recipients=[user.email])
        msg.body = body
        mail.send(msg)

# Function to create an admin user
def create_admin(name, email, phone, password, location=None, address=None, birthday=None):
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    admin_user = User(
        name=name,
        phone=phone,
        email=email,
        location=location,
        address=address,
        password=hashed_password,
        birthday=birthday,
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    print(f"Admin user {name} created successfully.")

# Function to create a super admin user
def create_super_admin(name, email, phone, password, location=None, address=None, birthday=None):
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    pin = str(random.randint(100000, 999999))  # Generate a random PIN for admin registrations
    super_admin_user = User(
        name=name,
        phone=phone,
        email=email,
        location=location,
        address=address,
        password=hashed_password,
        birthday=birthday,
        is_admin=True,
        is_super_admin=True,
        pin=pin
    )
    db.session.add(super_admin_user)
    db.session.commit()
    print(f"Super admin user {name} created successfully. Use this PIN for admin registrations: {pin}")

# Decorators to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract data from form
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        location = request.form.get('location')
        address = request.form.get('address')
        birthday_str = request.form.get('birthday')
        password = request.form['password']
        is_admin = 'admin' in request.form  # Check if admin checkbox is checked
        is_super_admin = 'super_admin' in request.form  # Check if super admin checkbox is checked
        pin = request.form.get('pin', '').strip()  # Get the PIN if provided

        # Validate required fields for all users
        if not name or not phone or not email or not password:
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')

        # If registering as a super admin, no PIN needed
        if is_super_admin and pin:
            flash('Super Admins do not need to provide a PIN.', 'error')
            return render_template('register.html')

        # If registering as an admin, validate the PIN
        if is_admin:
            if not pin:
                flash('Super Admin PIN is required for admin registration.', 'error')
                return render_template('register.html')

            # Check if the provided PIN matches the super admin's PIN
            super_admin = User.query.filter_by(is_super_admin=True).first()
            if not super_admin:
                flash('No Super Admin found in the database!', 'error')
                return render_template('register.html')

            # Ensure the super admin's PIN is checked correctly
            if super_admin.pin != pin:
                flash('Invalid Super Admin PIN!', 'error')
                return render_template('register.html')

        else:
            # If registering as a regular user, do not allow a PIN to be entered
            if pin:
                flash('Regular users do not need to provide a PIN.', 'error')
                return render_template('register.html')

        # Convert the birthday string to a date object if provided
        birthday = None
        if birthday_str:
            try:
                # Try parsing in 'YYYY-MM-DD' format
                birthday = datetime.strptime(birthday_str, "%Y-%m-%d").date()
            except ValueError:
                try:
                    # Try parsing in 'DD-MM-YYYY' format
                    birthday = datetime.strptime(birthday_str, "%d-%m-%Y").date()
                except ValueError:
                    flash('Invalid date format for birthday. Please use YYYY-MM-DD or DD-MM-YYYY.', 'error')
                    return render_template('register.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
            return render_template('register.html')

        # Create new user instance with admin or super admin roles
        new_user = User(
            name=name,
            phone=phone,
            email=email,
            location=location,
            address=address,
            password=hashed_password,
            birthday=birthday,
            is_admin=is_admin,  # Boolean directly assigned
            is_super_admin=is_super_admin  # Boolean directly assigned
        )

        # Try to add the user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'error')
            return render_template('register.html')

    return render_template('register.html')

# User login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["is_admin"] = user.is_admin
            session["is_super_admin"] = user.is_super_admin

            flash("Login successful!", "success")
            if user.is_super_admin or user.is_admin:
                return redirect(url_for("admin_dashboard"))  # Redirect to admin dashboard if super admin or admin
            else:
                return redirect(url_for("donate"))  # Redirect to donation page if regular user
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")


# Donation route
@app.route("/donate", methods=["GET", "POST"])
@login_required
def donate():
    if request.method == "POST":
        amount = request.form.get("amount")
        currency = request.form.get("currency")
        user_id = session.get("user_id")

        try:
            amount = float(amount)
            if amount <= 0:
                flash("Donation amount must be greater than zero.", "danger")
                return redirect(url_for("donate"))
        except (ValueError, TypeError):
            flash("Invalid amount format.", "danger")
            return redirect(url_for("donate"))

        if user_id:
            donation = Donation(user_id=user_id, amount=amount, currency=currency)

            try:
                db.session.add(donation)
                db.session.commit()
                flash("Thank you for your donation!", "success")
                app.logger.info(f"Donation saved: {donation.amount}, User ID: {user_id}")
                return redirect(url_for("donation_success"))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error saving donation: {e}")
                flash("An error occurred while processing your donation. Please try again.", "danger")
        else:
            flash("You need to be logged in to donate.", "danger")
            return redirect(url_for("login"))

    return render_template("donate.html")

# Donation success route
@app.route("/donation_success")
@login_required
def donation_success():
    return render_template("donation_success.html")

# Admin dashboard
@app.route("/admin_dashboard", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    # Handle bulk SMS and email
    if request.method == "POST":
        if "send_bulk_sms" in request.form:
            message = request.form["sms_message"]
            send_bulk_sms(message)
            flash("Bulk SMS sent successfully!", "success")
        elif "send_bulk_email" in request.form:
            subject = request.form["email_subject"]
            body = request.form["email_body"]
            send_bulk_email(subject, body)
            flash("Bulk email sent successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    # Fetch all donations and users
    donations = Donation.query.all()
    users = User.query.all()
    total_donations = sum(donation.amount for donation in donations)

    return render_template("admin_dashboard.html", recent_donations=donations, users=users, total_donations=total_donations)

# Route to delete a user
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user: {e}")
        flash("An error occurred while deleting the user.", "danger")
    return redirect(url_for("admin_dashboard"))

# Route to delete a donation
@app.route("/delete_donation/<int:donation_id>", methods=["POST"])
@admin_required
def delete_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    try:
        db.session.delete(donation)
        db.session.commit()
        flash("Donation deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting donation: {e}")
        flash("An error occurred while deleting the donation.", "danger")
    return redirect(url_for("admin_dashboard"))

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("index"))

# Error handling
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500

# Run the application
if __name__ == "__main__":
    app.run(debug=True)
