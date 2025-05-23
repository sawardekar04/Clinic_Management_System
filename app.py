from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'receptionist' or 'doctor'
    specialty = db.Column(db.String(100), nullable=True)  # Only for doctors
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    

    patients_created = db.relationship('Patient', foreign_keys='Patient.created_by', backref='creator')
    patients_updated = db.relationship('Patient', foreign_keys='Patient.last_updated_by', backref='updater')

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    experience_years = db.Column(db.Integer, nullable=False)
    
    user = db.relationship('User', backref=db.backref('doctor_profile', uselist=False))


class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    disease = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            flash(f'Welcome, {user.name}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

#  admin ko user create krne ke liye 
@app.route('/register', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'receptionist')
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        name = request.form['name']
        role = request.form['role']
        password = request.form['password']
        
        # Check if username or email already exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register'))
            
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            name=name,
            role=role,
            password=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # If role is doctor, create doctor profile
        if role == 'doctor':
            specialty = request.form['specialty']
            qualification = request.form['qualification']
            experience_years = request.form['experience_years']
            
            new_doctor = Doctor(
                user_id=new_user.id,
                specialty=specialty,
                qualification=qualification,
                experience_years=experience_years
            )
            
            db.session.add(new_doctor)
            db.session.commit()
        
        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('register.html')

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    patients = Patient.query.all()
    doctors = User.query.filter_by(role='doctor').all()
    
    # Count statistics
    patient_count = Patient.query.count()
    doctor_count = User.query.filter_by(role='doctor').count()
    
    # Different dashboard based on role
    if current_user.role == 'doctor':
        return render_template('doctor_dashboard.html', 
                              patients=patients, 
                              patient_count=patient_count,
                              doctor_count=doctor_count)
    else:  # receptionist or admin
        return render_template('dashboard.html', 
                              patients=patients, 
                              doctors=doctors,
                              patient_count=patient_count,
                              doctor_count=doctor_count)

# Add Patient route
@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'receptionist')
def add_patient():
    if request.method == 'POST':
        name = request.form.get('Patient-Name')
        age = request.form.get('Patient-Age')
        gender = request.form.get('Gender')
        phone = request.form.get('Patient-PhoneNo')
        date_str = request.form.get('Patient-Date')
        disease = request.form.get('Patient-desc')
        
        date = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else datetime.utcnow().date()
        
        new_patient = Patient(
            name=name, 
            age=age, 
            gender=gender, 
            phone=phone, 
            disease=disease, 
            date=date,
            created_by=current_user.id,
            last_updated_by=current_user.id
        )
        
        db.session.add(new_patient)
        db.session.commit()
        
        flash(f'Patient {name} has been added successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('add_patient.html')

# Delete Patient route
@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
@login_required
def delete_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    
    db.session.delete(patient)
    db.session.commit()
    
    flash(f'Patient {patient.name} has been deleted', 'success')
    return redirect(url_for('dashboard'))

# Update Patient route
@app.route('/update_patient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'receptionist')
def update_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        patient.name = request.form['Patient-Name']
        patient.age = request.form['Patient-Age']
        patient.gender = request.form['Gender']
        patient.phone = request.form['Patient-PhoneNo']
        patient.disease = request.form['Patient-desc']
        patient.last_updated_by = current_user.id
        
        db.session.commit()
        
        flash(f'Patient {patient.name} has been updated', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('update_patient.html', patient=patient)

# Patients by date route
@app.route('/patients_by_date')
@login_required
def patients_by_date():
    selected_date = request.args.get('date')
    
    if selected_date:
        try:
            date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()
            patients = Patient.query.filter_by(date=date_obj).all()
        except ValueError:
            patients = []
    else:
        patients = []
    
    return render_template('patients_by_date.html', patients=patients, selected_date=selected_date)

# Search patients route
@app.route('/search_patients')
@login_required
def search_patients():
    query = request.args.get('query', '')
    
    if query:
        # Search by name (case-insensitive)
        patients = Patient.query.filter(Patient.name.ilike(f'%{query}%')).all()
    else:
        patients = []
    
    return render_template('search_results.html', patients=patients, query=query)

# Add Doctor route (for admin)
@app.route('/add_doctor', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'receptionist')
def add_doctor():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        specialty = request.form['specialty']
        qualification = request.form['qualification']
        experience_years = request.form['experience_years']
        
        # Check if username or email already exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('add_doctor'))
            
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create new user with doctor role
        new_user = User(
            username=username,
            email=email,
            name=name,
            role='doctor',
            password=hashed_password,
            specialty=specialty
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create doctor profile
        new_doctor = Doctor(
            user_id=new_user.id,
            specialty=specialty,
            qualification=qualification,
            experience_years=experience_years
        )
        
        db.session.add(new_doctor)
        db.session.commit()
        
        flash(f'Doctor account created for {name}!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('add_doctor.html')

# Initialize the database and create admin user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(
                username='admin',
                password=hashed_password,
                name='Administrator',
                email='admin@clinic.com',
                role='admin'
            )
            db.session.add(admin)
            
            # Create a default receptionist
            hashed_password = bcrypt.generate_password_hash('reception123').decode('utf-8')
            receptionist = User(
                username='reception',
                password=hashed_password,
                name='Sahil Shaikh',
                email='sahilreception@clinic.com',
                role='Receptionist'
            )
            db.session.add(receptionist)
            
            # Create a default doctor
            hashed_password = bcrypt.generate_password_hash('doctor123').decode('utf-8')
            doctor = User(
                username='doctor',
                password=hashed_password,
                name='Dr. Smith',
                email='doctor@clinic.com',
                role='doctor',
                specialty='General Medicine'
            )
            db.session.add(doctor)
            db.session.commit()
            
            # Create doctor profile
            doctor_profile = Doctor(
                user_id=doctor.id,
                specialty='General Medicine',
                qualification='MD, General Medicine',
                experience_years=10
            )
            db.session.add(doctor_profile)
            db.session.commit()

# if __name__ == '__main__':
#     init_db()
#     app.run(host='0.0.0.0', debug=True)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)