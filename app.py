from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

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

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    location = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag

# Donation model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user = db.relationship("User", backref="donations")

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
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        
        # Check if the user is registering as admin
        is_admin = request.form.get("is_admin") == "on"  # 'on' means checked
        
        user = User(name=name, phone=phone, email=email, location=location, address=address, password=hashed_password, is_admin=is_admin)
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
            
            # Redirect based on user role
            if user.is_admin:  # If the user is an admin
                return redirect(url_for("admin_dashboard"))
            else:  # If the user is a regular user
                return redirect(url_for("donate"))  # Redirect to donate dashboard for users
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")

# Dashboard for donation tracking (user view)
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
            return redirect(url_for("login"))
        
        amount = float(request.form["amount"])
        donation = Donation(user_id=user_id, amount=amount)
        db.session.add(donation)
        db.session.commit()
        
        # Send acknowledgment email
        user = User.query.get(user_id)
        msg = Message("Donation Acknowledgement", sender="noreply@donationtracker.com", recipients=[user.email])
        msg.body = f"Dear {user.name},\n\nThank you for your generous donation of ${amount}.\nWe truly appreciate your support.\n\nBest regards,\nDonation Tracker Team"
        mail.send(msg)

        flash("Donation recorded and acknowledgment email sent.", "success")
        return redirect(url_for("dashboard"))

    return render_template("donate.html")

# Logout user
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("is_admin", None)  # Remove admin status from session
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
