
from flask_pymongo import PyMongo

from datetime import datetime, timedelta
import os
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'navi_x.db')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/navi_x"  # local MongoDB
# app.config["MONGO_URI"] = "your_atlas_connection_string"  # for Atlas
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'replace_this_with_a_secure_key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB max upload

CORS(app, supports_credentials=True)

mongo = PyMongo(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Models -------------------------------------------------
class Authority(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    doc_filename = db.Column(db.String(256))
    verified = db.Column(db.Boolean, default=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "department": self.department,
            "verified": self.verified,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "doc_filename": self.doc_filename
        }

class Bus:
    def __init__(self, name, route, lat=0.0, lng=0.0, status='On Time', driver='Unknown', speed=0, capacity=40, passengers=0):
        self.name = name
        self.route = route
        self.lat = lat
        self.lng = lng
        self.status = status
        self.driver = driver
        self.speed = speed
        self.capacity = capacity
        self.passengers = passengers
        self.updated_at = datetime.utcnow()

    def to_dict(self, include_id=True, mongo_id=None):
        data = {
            'name': self.name,
            'route': self.route,
            'lat': self.lat,
            'lng': self.lng,
            'status': self.status,
            'driver': self.driver,
            'speed': self.speed,
            'capacity': self.capacity,
            'passengers': self.passengers,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        if include_id and mongo_id:
            data['id'] = str(mongo_id)
        return data

# --- Helpers ------------------------------------------------
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes --------------------------------------------------


@app.route('/api/register', methods=['POST'])
def register_authority():
    # Accepts multipart/form-data with fields: username, email, department, password, file
    username = request.form.get('username')
    email = request.form.get('email')
    department = request.form.get('department')
    password = request.form.get('password')
    file = request.files.get('file')

    if not (username and email and password and department and file):
        return jsonify({'msg': 'Missing required fields'}), 400

    if not allowed_file(file.filename):
        return jsonify({'msg': 'File type not allowed'}), 400

    if Authority.query.filter((Authority.username == username) | (Authority.email == email)).first():
        return jsonify({'msg': 'Username or email already registered'}), 400

    filename = secure_filename(f"{username}_{int(datetime.utcnow().timestamp())}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    auth = Authority(
        username=username,
        email=email,
        department=department,
        password_hash=generate_password_hash(password),
        doc_filename=filename,
        verified=True  # In a real app, set false and verify manually
    )
    db.session.add(auth)
    db.session.commit()

    return jsonify({'msg': 'Registration successful', 'authority': auth.to_dict()}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    identifier = data.get('identifier')
    password = data.get('password')

    if not identifier or not password:
        return jsonify({'msg': 'Missing credentials'}), 400

    auth = Authority.query.filter((Authority.username == identifier) | (Authority.email == identifier)).first()
    if not auth or not auth.check_password(password):
        return jsonify({'msg': 'Bad username/email or password'}), 401

    access_token = create_access_token(identity=auth.username, expires_delta=timedelta(hours=8))

    return jsonify({'access_token': access_token, 'authority': auth.to_dict()}), 200

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Serve uploaded files (only for development)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Bus endpoints ------------------------------------------
@app.route('/api/buses', methods=['GET'])
def list_buses():
    buses = Bus.query.all()
    return jsonify([b.to_dict() for b in buses])

@app.route('/api/buses', methods=['POST'])
@jwt_required()
def add_bus():
    data = request.get_json(force=True)
    name = data.get('name')
    route = data.get('route')
    lat = data.get('lat', 0.0)
    lng = data.get('lng', 0.0)
    driver = data.get('driver', 'New Driver')

    if not name or not route:
        return jsonify({'msg': 'Name and route are required'}), 400

    bus = Bus(name=name, route=route, lat=lat, lng=lng, driver=driver)
    db.session.add(bus)
    db.session.commit()
    return jsonify({'msg': 'Bus added', 'bus': bus.to_dict()}), 201

@app.route('/api/buses/<int:bus_id>', methods=['PUT'])
@jwt_required()
def update_bus(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    data = request.get_json(force=True)

    for field in ('name', 'route', 'lat', 'lng', 'status', 'driver', 'speed', 'capacity', 'passengers'):
        if field in data:
            setattr(bus, field, data[field])

    db.session.commit()
    return jsonify({'msg': 'Updated', 'bus': bus.to_dict()}), 200

@app.route('/api/buses/<int:bus_id>/action', methods=['POST'])
@jwt_required()
def bus_action(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    data = request.get_json(force=True)
    action = data.get('action')

    if action == 'emergency_stop':
        bus.status = 'Emergency Stop'
    elif action == 'set_status' and 'status' in data:
        bus.status = data['status']
    elif action == 'update_passengers' and 'passengers' in data:
        bus.passengers = int(data['passengers'])
    else:
        return jsonify({'msg': 'Unknown action or missing parameters'}), 400

    db.session.commit()
    return jsonify({'msg': 'Action applied', 'bus': bus.to_dict()}), 200

@app.route('/api/emergency', methods=['POST'])
@jwt_required()
def emergency_all():
    # Set all buses to Emergency Stop
    buses = Bus.query.all()
    for b in buses:
        b.status = 'Emergency Stop'
    db.session.commit()
    return jsonify({'msg': 'Emergency applied to all buses', 'affected': len(buses)}), 200

@app.route('/api/report', methods=['GET'])
@jwt_required()
def generate_report():
    buses = Bus.query.all()
    report = []
    for b in buses:
        report.append(f"{b.name} - {b.route} - {b.status} - {b.passengers}/{b.capacity} passengers")
    return jsonify({'report': report}), 200

# --- Simple bootstrap endpoint for dev ---------------------
@app.route('/')
def index():
    return jsonify({'msg': 'Navi X backend alive'})

# --- Seed some buses for development -----------------------
@app.cli.command('seed')
def seed_data():
    if Bus.query.count() == 0:
        sample = [
            {'name': 'BGarden', 'route': 'Route 101'},
            {'name': 'L238', 'route': 'Route 202'},
            {'name': 'DN17', 'route': 'Route 303'},
            {'name': 'Airport D4', 'route': 'Route 404'},
            {'name': 'University E5', 'route': 'Route 505'},
            {'name': 'Hospital F6', 'route': 'Route 606'},
        ]
        for s in sample:
            b = Bus(name=s['name'], route=s['route'], lat=22.5726 + (0.01 - 0.02 * (s['name'].__hash__() % 10)), lng=88.3639 + (0.01 - 0.02 * (s['route'].__hash__() % 10)), status='On Time', driver='Driver X', speed=20)
            db.session.add(b)
        db.session.commit()
        print('Seeded buses')
    else:
        print('Buses already present')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # ✅ This creates all tables before starting the app
    app.run(debug=True)

