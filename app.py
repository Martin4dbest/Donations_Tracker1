from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from twilio.rest import Client
import random

# App and database setup
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///donations.db"
app.config["SECRET_KEY"] = "randomsecretkey"
app.config["MAIL_SERVER"] = "smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USERNAME"] = "your_mailtrap_username"  # Update with your Mailtrap username
app.config["MAIL_PASSWORD"] = "your_mailtrap_password"  # Update with your Mailtrap password
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
scheduler = BackgroundScheduler()

# Twilio configuration
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
    birthday = db.Column(db.Date, nullable=True)  # Add birthday column
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag
    is_super_admin = db.Column(db.Boolean, default=False)  # Super Admin flag
    pin = db.Column(db.String(6), nullable=True)  # Field to store admin registration PIN

# Donation model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='USD')  # Add currency column
    user = db.relationship("User", backref="donations")

# Schedule for sending birthday emails
def send_birthday_emails():
    today = datetime.now().date()
    users_with_birthday = User.query.filter(db.func.strftime('%m-%d', User.birthday) == today.strftime('%m-%d')).all()
    for user in users_with_birthday:
        msg = Message("Happy Birthday!", sender="noreply@donationtracker.com", recipients=[user.email])
        msg.body = f"Dear {user.name},\n\nHappy Birthday! We wish you a wonderful day!\n\nBest regards,\nDonation Tracker Team"
        mail.send(msg)

scheduler.add_job(send_birthday_emails, 'cron', day='*', hour=0)  # Runs every day at midnight
scheduler.start()

# Function to send bulk SMS
def send_bulk_sms(message):
    users = User.query.all()  # Get all users
    for user in users:
        client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=user.phone
        )

# Function to send bulk emails
def send_bulk_email(subject, body):
    users = User.query.all()  # Get all users
    for user in users:
        msg = Message(subject, sender="noreply@donationtracker.com", recipients=[user.email])
        msg.body = body
        mail.send(msg)

# Function to create an admin user
def create_admin(name, email, phone, password, location=None, address=None, birthday=None):
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    admin_user = User(name=name, phone=phone, email=email, location=location, address=address,
                      password=hashed_password, birthday=birthday, is_admin=True)  # is_admin=True for admin
    db.session.add(admin_user)
    db.session.commit()
    print(f"Admin user {name} created successfully.")

# Function to create a super admin user
def create_super_admin(name, email, phone, password, location=None, address=None, birthday=None):
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    pin = str(random.randint(100000, 999999))  # Generate a random PIN for the super admin
    super_admin_user = User(name=name, phone=phone, email=email, location=location, address=address,
                            password=hashed_password, birthday=birthday, is_admin=True, is_super_admin=True, pin=pin)  # Set is_super_admin=True
    db.session.add(super_admin_user)
    db.session.commit()
    print(f"Super admin user {name} created successfully. Use this PIN for other admin registrations: {pin}")

# Home route
@app.route("/")
def index():
    return render_template("index.html")

# Admin registration route
@app.route('/register_admin', methods=['POST'])
def register_admin():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password']
    location = request.form['location']
    address = request.form['address']
    birthday_str = request.form['birthday']
    pin = request.form['pin']  # Get the PIN from the form
    
    # Check if the provided PIN matches the super admin's PIN
    super_admin = User.query.filter_by(is_super_admin=True).first()  # Get the super admin (assuming only 1 super admin)
    if super_admin and super_admin.pin == pin:
        # If the PIN is correct, create an admin
        birthday = datetime.strptime(birthday_str, "%Y-%m-%d").date()
        create_admin(name, email, phone, password, location, address, birthday)
        flash("Admin registered successfully!")
        return redirect(url_for('admin_dashboard'))
    else:
        flash("Invalid Super Admin PIN!")
        return redirect(url_for('register_admin'))
    

    
# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract data from form
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        location = request.form['location']
        address = request.form['address']
        birthday_str = request.form['birthday']  # Birthday as string
        password = request.form['password']
        is_admin = 'admin' in request.form  # Check if admin checkbox is checked
        pin = request.form.get('pin')  # Get the PIN if provided

        # Validate required fields for all users
        if not name or not phone or not email or not password:
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')

        # If registering as an admin, validate the PIN
        if is_admin and not pin:
            flash('Super Admin PIN is required for admin registration.', 'error')
            return render_template('register.html')

        # If registering as an ordinary user, do not allow PIN to be entered
        if not is_admin and pin:
            flash('Ordinary users do not need to provide a PIN.', 'error')
            return render_template('register.html')

        # Convert the birthday string to a date object
        try:
            birthday = datetime.strptime(birthday_str, "%Y-%m-%d").date()
        except ValueError:
            flash('Invalid date format for birthday. Please use YYYY-MM-DD.', 'error')
            return render_template('register.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
            return render_template('register.html')

        # Create new user instance
        new_user = User(
            name=name,
            phone=phone,
            email=email,
            location=location,
            address=address,
            password=hashed_password,
            birthday=birthday,
            is_admin=is_admin
        )

        # Try to add the user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')  # Added flash message
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()  # Rollback the session on error
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
            session["is_admin"] = user.is_admin  # Set admin status in session
            session["is_super_admin"] = user.is_super_admin  # Set super admin status in session
            
            flash("Login successful!", "success")
            return redirect(url_for("admin_dashboard") if user.is_super_admin else url_for("donate"))
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")

@app.route("/donate", methods=["GET", "POST"])
def donate():
    if request.method == "POST":
        amount = request.form["amount"]
        currency = request.form["currency"]
        user_id = session.get("user_id")

        # Validate and convert the donation amount
        try:
            amount = float(amount)
            if amount <= 0:
                flash("Donation amount must be greater than zero.", "danger")
                return redirect(url_for("donate"))
        except ValueError:
            flash("Invalid amount format.", "danger")
            return redirect(url_for("donate"))

        if user_id:
            donation = Donation(user_id=user_id, amount=amount, currency=currency)

            try:
                db.session.add(donation)
                db.session.commit()
                flash("Thank you for your donation!", "success")
                # Redirect to a confirmation page or the dashboard
                return redirect(url_for("donation_success"))  # Adjust to your success page
            except Exception as e:
                db.session.rollback()
                flash("An error occurred while processing your donation. Please try again.", "danger")
        else:
            flash("You need to be logged in to donate.", "danger")

        return redirect(url_for("donate"))

    return render_template("donate.html")


# Admin dashboard
@app.route("/admin_dashboard")
def admin_dashboard():
    donations = Donation.query.all()  # Fetch all donations
    return render_template("admin_dashboard.html", donations=donations)

# Bulk SMS route
@app.route("/bulk_sms", methods=["POST"])
def bulk_sms():
    message = request.form["message"]
    send_bulk_sms(message)
    flash("Bulk SMS sent successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Bulk Email route
@app.route("/bulk_email", methods=["POST"])
def bulk_email():
    subject = request.form["subject"]
    body = request.form["body"]
    send_bulk_email(subject, body)
    flash("Bulk email sent successfully!", "success")
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
