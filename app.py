from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from twilio.rest import Client

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

# Call this function manually to create an admin user


# Home route
@app.route("/")
def index():
    return render_template("index.html")

# User registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]
        location = request.form["location"]
        address = request.form["address"]
        password = request.form["password"]
        birthday = request.form.get("birthday")  # Get birthday input
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        is_admin = request.form.get("is_admin") == "on"  # 'on' means checked
        
        user = User(name=name, phone=phone, email=email, location=location, address=address, password=hashed_password, birthday=datetime.strptime(birthday, '%Y-%m-%d') if birthday else None, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

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
            
            flash("Login successful!", "success")
            return redirect(url_for("admin_dashboard") if user.is_admin else "donate")
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")

# User dashboard
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    donations = Donation.query.filter_by(user_id=session["user_id"]).all()
    return render_template("dashboard.html", donations=donations)

# Admin dashboard
@app.route("/admin_dashboard")
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    users = User.query.all()
    donations = Donation.query.all()

    total_donations = db.session.query(db.func.sum(Donation.amount)).scalar() or 0
    recent_donations = Donation.query.order_by(Donation.id.desc()).limit(10).all()

    return render_template(
        "admin_dashboard.html", 
        users=users, 
        donations=donations, 
        total_donations=total_donations, 
        recent_donations=recent_donations
    )

# Add donation
@app.route("/donate", methods=["GET", "POST"])
def donate():
    if request.method == "POST":
        user_id = session.get("user_id")
        if not user_id:
            flash("You must be logged in to donate.", "danger")
            return redirect(url_for("login"))
        
        try:
            amount = float(request.form["amount"])
            currency = request.form.get("currency", "USD")  # Get currency input, default to USD
            donation = Donation(user_id=user_id, amount=amount, currency=currency)
            db.session.add(donation)
            db.session.commit()
            
            # Send acknowledgment email
            user = User.query.get(user_id)
            msg = Message("Donation Acknowledgement", sender="noreply@donationtracker.com", recipients=[user.email])
            msg.body = f"Dear {user.name},\n\nThank you for your generous donation of {currency} {amount}.\nWe truly appreciate your support.\n\nBest regards,\nDonation Tracker Team"
            mail.send(msg)

            flash("Donation recorded and acknowledgment email sent.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("donate"))

    return render_template("donate.html")



# Trigger bulk email sending
@app.route("/send_bulk_email", methods=["POST"])
def trigger_bulk_email():
    subject = request.form.get("subject")
    body = request.form.get("body")
    send_bulk_email(subject, body)
    flash("Bulk email sent!", "success")
    return redirect(url_for("admin_dashboard"))

# Route to trigger bulk SMS sending
@app.route("/send_bulk_sms", methods=["POST"])
def trigger_bulk_sms():
    sms_body = request.form.get("sms_body")
    send_bulk_sms(sms_body)
    flash("Bulk SMS sent!", "success")
    return redirect(url_for("admin_dashboard"))

# Delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('admin_dashboard'))

# Delete donation
@app.route('/delete_donation/<int:donation_id>', methods=['POST'])
def delete_donation(donation_id):
    donation = Donation.query.get(donation_id)
    if donation:
        db.session.delete(donation)
        db.session.commit()
        flash('Donation deleted successfully!', 'success')
    else:
        flash('Donation not found.', 'error')
    return redirect(url_for('admin_dashboard'))

# Logout
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("is_admin", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
