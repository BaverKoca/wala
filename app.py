import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv

# Ortam değişkenlerini yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'varsayilan_gizli_anahtar')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wala.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)

# Veritabanı Modelleri
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    return render_template('chat.html', messages=messages, username=session['username'])

# Oturumu Sonlandır
@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('login'))

# WebSocket Mesaj Gönderimi
@socketio.on('send_message')
def handle_message(data):
    msg = Message(username=data['username'], content=data['message'])
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {
        'username': data['username'],
        'message': data['message'],
        'timestamp': msg.timestamp.strftime('%H:%M:%S')
    }, broadcast=True)

# Ana Uygulama
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)
# Uygulama başlatıldığında varsayılan olarak SQLite veritabanı oluşturulur.
# Eğer veritabanı dosyası yoksa, uygulama başlatıldığında otomatik olarak oluşturulur.