from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///attendance.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="student")  # Either 'student' or 'admin'
    subjects_registered = db.Column(db.Integer, default=0)
    classes_missed = db.Column(db.Integer, default=0)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    attended_classes = db.Column(db.Integer, default=0)
    missed_classes = db.Column(db.Integer, default=0)

# Add relationships
User.subjects = db.relationship('Subject', secondary='user_subject', backref='students')
class UserSubject(db.Model):
    __tablename__ = 'user_subject'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), primary_key=True)

# Initialize database
with app.app_context():
    db.create_all()

# Routes
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        role = "student"  # Default role

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another.", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("home"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash(f"Welcome, {user.username}!", "success")

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("student_dashboard"))
        else:
            flash("Invalid username or password. Please try again.", "danger")
            return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/student_dashboard")
def student_dashboard():
    if "user_id" not in session or session["role"] != "student":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    user = User.query.get(session["user_id"])
    return render_template(
        "student_dashboard.html",
        username=user.username,
        subjects_registered=user.subjects_registered,
        classes_missed=user.classes_missed,
    )

@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session or session["role"] != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    users = User.query.filter_by(role="student").all()
    return render_template("admin_dashboard.html", users=users)

@app.route("/register_subject", methods=["GET", "POST"])
def register_subject():
    if "user_id" not in session or session["role"] != "student":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    user = User.query.get(session["user_id"])
    subjects = Subject.query.all()

    if request.method == "POST":
        subject_id = request.form["subject_id"]
        subject = Subject.query.get(subject_id)

        if subject in user.subjects:
            flash("You have already registered for this subject.", "warning")
        else:
            user.subjects.append(subject)
            attendance = Attendance(user_id=user.id, subject_id=subject.id)
            db.session.add(attendance)
            db.session.commit()
            flash(f"Subject '{subject.name}' registered successfully.", "success")

    return render_template("register_subject.html", subjects=subjects, user_subjects=user.subjects)

@app.route("/mark_attendance", methods=["GET", "POST"])
def mark_attendance():
    if "user_id" not in session or session["role"] != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    subjects = Subject.query.all()
    students = User.query.filter_by(role="student").all()

    if request.method == "POST":
        user_id = request.form["user_id"]
        subject_id = request.form["subject_id"]
        status = request.form["status"]  # "present" or "absent"

        attendance = Attendance.query.filter_by(user_id=user_id, subject_id=subject_id).first()
        if not attendance:
            flash("No attendance record found.", "danger")
        else:
            if status == "present":
                attendance.attended_classes += 1
            elif status == "absent":
                attendance.missed_classes += 1
            db.session.commit()
            flash("Attendance marked successfully.", "success")

    return render_template("mark_attendance.html", students=students, subjects=subjects)

@app.route("/analytics")
def analytics():
    if "user_id" not in session:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    user = User.query.get(session["user_id"])
    if user.role == "student":
        attendance_records = Attendance.query.filter_by(user_id=user.id).all()
        return render_template("student_analytics.html", attendance_records=attendance_records)

    elif user.role == "admin":
        attendance_records = Attendance.query.all()
        return render_template("admin_analytics.html", attendance_records=attendance_records)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
