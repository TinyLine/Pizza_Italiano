from flask import Flask, render_template, request, redirect, url_for, flash, session

from flask_login import login_required, current_user, login_user, logout_user # pip install flask-login

from db import Session, Users, Menu, Orders, Reservation
from flask_login import LoginManager
from datetime import datetime

import os
import uuid

import secrets

app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  # 1MB
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['SECRET_KEY'] = '#cv)3v7w$*s3fk;5c!@y0?:?№3"9)#'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id = user_id).first()
        if user:
            return user

@app.after_request
def apply_csp(response):
    nonce = secrets.token_urlsafe(16)  
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.set_cookie('nonce', nonce)
    return response

@app.route('/')
@app.route('/home')
def home():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Запит заблоковано!", 403

        password = request.form.get('password')
        if not password or len(password) < 8:
            flash('Пароль має містити не менше 8 символів.')
            return redirect(url_for('register'))

        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname=nickname).first():
                flash('Користувач з таким email або нікнеймом вже існує!', 'danger')
                return render_template('register.html', csrf_token=session["csrf_token"])

            new_user = Users(nickname=nickname, email=email)
            new_user.set_password(password)
            cursor.add(new_user)
            cursor.commit()
            cursor.refresh(new_user)
            login_user(new_user)
            return redirect(url_for('home'))

    session["csrf_token"] = secrets.token_hex(16)
    return render_template('register.html', csrf_token=session["csrf_token"])


@app.route("/login", methods = ["GET","POST"])
def login():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        nickname = request.form['nickname']
        password = request.form['password']

        with Session() as cursor:
            user = cursor.query(Users).filter_by(nickname = nickname).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))

            flash('Неправильний nickname або пароль!', 'danger')

        if request.method == 'GET':
         session["csrf_token"] = secrets.token_hex(16)

    return render_template('login.html', csrf_token=session["csrf_token"])


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route("/add_position", methods=['GET', 'POST'])
@login_required
def add_position():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']

        if not file or not file.filename:
            return 'Файл не вибрано або завантаження не вдалося'

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join('static/menu', unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name=name, ingredients=ingredients, description=description,
                                price=price, weight=weight, file_name=unique_filename)
            cursor.add(new_position)
            cursor.commit()

        flash('Позицію додано успішно!')

    return render_template('add_position.html', csrf_token=session["csrf_token"])


@app.route('/menu')
def menu():
    with Session() as session:
        all_positions = session.query(Menu).filter_by(active = True).all()
    return render_template('menu.html',all_positions = all_positions)

@app.route('/position/<name>', methods = ['GET','POST'])
def position(name):
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        position_name = request.form.get('name')
        position_num = request.form.get('num')
        if 'basket' not in session:
            basket = {}
            basket[position_name] = position_num
            session['basket'] = basket
        else:
            basket = session.get('basket')
            if basket is None:
                basket = {}
            basket[position_name] = position_num
            session['basket'] = basket
        flash('Позицію додано у кошик!')
    with Session() as cursor:
        us_position = cursor.query(Menu).filter_by(active = True, name = name).first()
    return render_template('position.html', csrf_token=session["csrf_token"] ,position = us_position)

@app.route('/test_basket')
def test_basket():
    basket = session.get('basket', {})
    return basket


@app.route('/create_order', methods=['GET','POST'])
def create_order():
    basket = session.get('basket')
    if request.method == 'POST':

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        if not current_user:
            flash("Для оформлення замовлення необхідно бути зареєстрованим")
        else:
            if not basket:
                flash("Ваш кошик порожній")
            else:
                with Session() as cursor:
                    new_order = Orders(order_list = basket,order_time = datetime.now(), user_id=current_user.id)
                    cursor.add(new_order)
                    cursor.commit()
                    session.pop('basket')
                    cursor.refresh(new_order)
                    return redirect(f"/my_order/{new_order.id}")

    return render_template('create_order.html', csrf_token=session["csrf_token"], basket=basket)

@app.route('/menu_check', methods=['GET', 'POST'])
@login_required
def menu_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form.get("csrf_token") != session['csrf_token']:
            return "Запит заблоковано!", 403

        position_id = request.form['pos_id']
        with Session() as cursor:
            position_obj = cursor.query(Menu).filter_by(id=position_id).first()
            if 'change_status' in request.form:
                position_obj.active = not position_obj.active
            elif 'delete_position' in request.form:
                cursor.delete(position_obj)
            cursor.commit()

    with Session() as cursor:
        all_positions = cursor.query(Menu).all()
    return render_template('check_menu.html', all_positions=all_positions, csrf_token=session["csrf_token"])

@app.route('/all_users')
@login_required
def all_users():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        all_users = cursor.query(Users).with_entities(Users.id, Users.nickname, Users.email).all()
    return render_template('all_users.html', all_users=all_users)