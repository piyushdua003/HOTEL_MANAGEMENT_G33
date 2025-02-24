from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.exceptions import InternalServerError
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config['SECRET_KEY'] = 'my_secret_key'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")
    username = db.Column(db.String(100), nullable=False, unique=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class RoomAllocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostel = db.Column(db.String(20), nullable=False)
    floor = db.Column(db.Integer, nullable=False)
    room_number = db.Column(db.Integer, nullable=False)
    room_type = db.Column(db.String(10), nullable=False)
    beds_left = db.Column(db.Integer, nullable=False, default=4)  # Added beds_left column
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_name = db.Column(db.String(50), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('hostel', 'floor', 'room_number', 'user_id', name='uq_hostel_floor_room_user'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ensure the database and tables are created
with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user is None:
        admin_user = User(
            name="Admin",
            email="admin@example.com",
            username="admin",
            role="admin"
        )
        admin_user.set_password("password123")
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/room_allocation', methods=['GET', 'POST'])
@login_required
def room_allocation():
    if request.method == 'POST':
        try:
            hostel = request.form['hostel']
            floor = int(request.form['floor'])
            room_number = int(request.form['room-number'])
            room_type = request.form['room-type']
            student_name = request.form['student-name']

            print("Received data:", {
                "hostel": hostel,
                "floor": floor,
                "room_number": room_number,
                "room_type": room_type,
                "student_name": student_name
            })

            # Check if the room already exists
            room = RoomAllocation.query.filter_by(room_number=room_number).first()

            if not room:
                # If the room doesn't exist, create it
                beds_left = 4 if room_type == "four" else (2 if room_type == "double" else 1)
                room = RoomAllocation(
                    hostel=hostel, 
                    floor=floor, 
                    room_number=room_number,
                    room_type=room_type, 
                    beds_left=beds_left - 1, 
                    user_id=current_user.id,  # Set the user_id to the current user's ID
                    student_name=student_name
                )
                db.session.add(room)
                db.session.commit()
                print("Room created successfully!")
                return jsonify({'message': 'Room allocated successfully!', 'success': True})
            
            elif room.beds_left > 0:
                # If the room exists and has beds left, allocate it
                room.beds_left -= 1
                room.student_name = student_name
                room.user_id = current_user.id  # Set the user_id to the current user's ID
                db.session.commit()
                print("Room allocated successfully!")
                return jsonify({'message': 'Room allocated successfully!', 'success': True})
            
            else:
                # If the room is full
                print("Room is full!")
                return jsonify({'message': 'Room not available!', 'success': False})

        except Exception as e:
            print("Error:", str(e))
            return jsonify({'message': f'Internal Server Error: {str(e)}', 'success': False}), 500

    return render_template('room_allocation.html')

@app.route('/get_available_rooms', methods=['GET'])
def get_available_rooms():
    # Get selected hostel and floor from the request
    selected_hostel = request.args.get('hostel', default='hostel-1')
    selected_floor = int(request.args.get('floor', default=1))

    # Define room numbers based on hostel and floor
    base_room = {
        "hostel-1": 0,
        "hostel-2": 0,
        "hostel-3": 0,
        "hostel-4": 0,
    }
    room_offset = base_room.get(selected_hostel, 100)  # Default to hostel-1 if invalid
    room_start = room_offset + (selected_floor * 100)  # Example: hostel-1, floor 2 → 100 + 200 = 300
    predefined_rooms = {
        "four": list(range(room_start + 1, room_start + 17)),   # Rooms 101-116 for hostel-1 floor 1
        "double": list(range(room_start + 18, room_start + 25)),  # Rooms 201-217 for hostel-1 floor 2
        "single": list(range(room_start + 26, room_start + 35))   # Rooms 301-318 for hostel-1 floor 3
    }

    available = {"four": [], "double": [], "single": []}
    booked = []

    for room_type, numbers in predefined_rooms.items():
        max_beds = 4 if room_type == 'four' else 2 if room_type == 'double' else 1
        for number in numbers:
            count = RoomAllocation.query.filter_by(
                hostel=selected_hostel,
                floor=selected_floor,
                room_number=number,
                room_type=room_type
            ).count()
            beds_left = max_beds - count
            if beds_left > 0:
                available[room_type].append({'number': number, 'beds_left': beds_left})
            else:
                booked.append(number)
    return jsonify({"available": available, "booked": booked})

@app.route('/terms_and_conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/complaint_and_maintenance')
@login_required
def complaint_and_maintenance():
    return render_template('complaint_and_maintenance.html')

@app.route('/feedback')
def feedback():
    if 'username' not in session:
        flash('You need to log in to access this section', 'danger')
        return redirect(url_for('login'))
    return render_template('feedback.html')

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/hostel_details')
def hostel_details():
    if 'username' not in session:
        flash('You need to log in to access this section', 'danger')
        return redirect(url_for('login'))
    return render_template('hostel_details.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        print("Role selected in form:", role)
        print("Email entered:", email)

        user = User.query.filter_by(email=email, role=role).first()
        print("Query:", User.query.filter_by(email=email, role=role))

        if user and user.check_password(password):
            login_user(user)
            session['username'] = user.name  # Store username in session
            flash("Login successful!", "success")
            if user.role == "admin":
                return redirect(url_for("dashboard"))  # Redirect admin to dashboard
            else:
                return redirect(url_for("home"))  # Redirect normal users to home
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('login'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('login'))
        new_user = User(name=name, email=email, username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.id)
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('dashboard.html', users=users)

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if user:
        user.name = request.form['name']
        user.email = request.form['email']
        user.username = request.form['username']
        db.session.commit()
        flash('User updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True)