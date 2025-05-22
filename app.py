import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Ortam değişkenlerini yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'varsayilan_gizli_anahtar')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wala.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt_gizli_anahtar')

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app)

# Veritabanı Modelleri
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)

# Ana Sayfa → Giriş yapılmışsa chat'e yönlendir
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

# Kayıt Sayfası
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Bu kullanıcı adı zaten alınmış.", "danger")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Kayıt başarılı! Giriş yapabilirsiniz.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Giriş Sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            flash("Giriş başarılı.", "success")
            return redirect(url_for('chat'))
        else:
            flash("Kullanıcı adı veya şifre hatalı.", "danger")
    return render_template('login.html')

# Sohbet Sayfası
@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=messages, username=session['username'], room=None)

# Odalar Sayfası
@app.route('/rooms', methods=['GET', 'POST'])
def rooms():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        room_name = request.form['room_name'].strip()
        if room_name and not Room.query.filter_by(name=room_name).first():
            db.session.add(Room(name=room_name))
            db.session.commit()
    all_rooms = Room.query.all()
    return render_template('rooms.html', rooms=all_rooms, username=session['username'])

# Odaya Özel Sohbet Sayfası
@app.route('/chat/<int:room_id>')
def chat_room(room_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=messages, username=session['username'], room=room)

@socketio.on('send_message')
def handle_message(data):
    file_info = data.get('file')
    file_url = None
    file_type = None
    file_name = None
    room_id = data.get('room_id')
    if file_info:
        import base64, uuid
        file_data = file_info['data'].split(',')[1] if ',' in file_info['data'] else file_info['data']
        ext = file_info['name'].split('.')[-1]
        file_name = f"{uuid.uuid4()}.{ext}"
        file_path = os.path.join('static', file_name)
        with open(file_path, 'wb') as f:
            f.write(base64.b64decode(file_data))
        file_url = f"/static/{file_name}"
        file_type = file_info['type']
    msg = Message(username=data['username'], content=data['message'], room_id=room_id)
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {
        'id': msg.id,
        'username': data['username'],
        'message': data['message'],
        'timestamp': msg.timestamp.strftime('%H:%M:%S'),
        'is_read': msg.is_read,
        'file': file_url and {
            'url': file_url,
            'type': file_type,
            'name': file_info['name'] if file_info else None
        },
        'room_id': room_id
    }, room=str(room_id) if room_id else None, broadcast=not room_id)

# WebSocket Mesaj Okundu İşlemi
@socketio.on('read_message')
def handle_read_message(data):
    msg_id = data.get('message_id')
    msg = Message.query.get(msg_id)
    if msg and not msg.is_read:
        msg.is_read = True
        db.session.commit()
        emit('message_read', {'message_id': msg_id}, broadcast=True)

# API: Kullanıcı Kaydı (JWT ile)
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return {'msg': 'Kullanıcı adı ve şifre gerekli.'}, 400
    if User.query.filter_by(username=username).first():
        return {'msg': 'Bu kullanıcı adı zaten alınmış.'}, 409
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    access_token = create_access_token(identity=username)
    return {'msg': 'Kayıt başarılı.', 'access_token': access_token}, 201

# API: Giriş (JWT ile)
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=username)
        return {'msg': 'Giriş başarılı.', 'access_token': access_token}, 200
    return {'msg': 'Kullanıcı adı veya şifre hatalı.'}, 401

# API: Mesajları Getir (JWT korumalı)
@app.route('/api/messages', methods=['GET'])
@jwt_required()
def api_get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return {'messages': [
        {
            'username': m.username,
            'content': m.content,
            'timestamp': m.timestamp.isoformat()
        } for m in messages
    ]}

# API: Mesaj Gönder (JWT korumalı)
@app.route('/api/messages', methods=['POST'])
@jwt_required()
def api_send_message():
    data = request.get_json()
    content = data.get('content', '').strip()
    if not content:
        return {'msg': 'Mesaj içeriği boş olamaz.'}, 400
    username = get_jwt_identity()
    msg = Message(username=username, content=content)
    db.session.add(msg)
    db.session.commit()
    return {'msg': 'Mesaj gönderildi.'}, 201

# Çevrimdışı sayfa route'u (PWA için)
@app.route('/offline')
def offline():
    return render_template('offline.html')

# Çıkış Yapma
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('login'))

# Ana Uygulama
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5001)
# Uygulama başlatıldığında varsayılan olarak SQLite veritabanı oluşturulur.
# Eğer veritabanı dosyası yoksa, uygulama başlatıldığında otomatik olarak oluşturulur.