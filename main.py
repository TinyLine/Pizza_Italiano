from flask import Flask, render_template, request, redirect, url_for, flash, session

from flask_login import login_required, current_user, login_user, logout_user # pip install flask-login

from db import Session, Users, Menu, Orders, Reservation
from flask_login import LoginManager
from datetime import datetime
from geopy.distance import geodesic

import os
import uuid

import secrets

MARGANETS_COORDS = (48.0159, 34.6278)
TABLE_NUM = {
    "1-2": 10,
    "3-4": 5,
    "4+": 2
}
KYIV_RADIUS_KM = 50


app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 МБ
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  # 1 МБ
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['SECRET_KEY'] = '#cv)3v7w$*s3fk;5c!@y0?:?№3"9)#'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id=user_id).first()
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
            flash('Пароль має містити не менше 8 символів.', 'danger')
            return redirect(url_for('register'))

        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname=nickname).first():
                flash('Користувач з таким email або нікнеймом уже існує!', 'danger')
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        nickname = request.form['nickname']
        password = request.form['password']

        with Session() as cursor:
            user = cursor.query(Users).filter_by(nickname=nickname).first()
            if user and user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('menu'))

            flash('Неправильний нікнейм або пароль!', 'danger')

    if request.method == 'GET':
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('login.html', csrf_token=session["csrf_token"])

@app.route('/profile')
@login_required
def profile():
    basket = session.get('basket', {})
    return render_template('profile.html', user=current_user, basket=basket)

@app.route("/add_position", methods=['GET', 'POST'])
@login_required
def add_position():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))

    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Запит заблоковано!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']

        if not file or not file.filename:
            return 'Файл не вибрано або завантаження не вдалося!'

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join('static/menu', unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name=name, ingredients=ingredients, description=description,
                                price=price, weight=weight, file_name=unique_filename)
            cursor.add(new_position)
            cursor.commit()

        flash('Позицію додано успішно!', 'success')

    return render_template('add_position.html', csrf_token=session["csrf_token"])

@app.route('/menu')
@login_required
def menu():
    with Session() as session:
        all_positions = session.query(Menu).filter_by(active=True).all()
    return render_template('menu.html', all_positions=all_positions)

@app.route('/position/<name>', methods=['GET', 'POST'])
@login_required
def position(name):
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        position_name = request.form.get('name')
        position_num = request.form.get('num')
        try:
            if position_num is None:
                raise ValueError("No quantity provided")
            position_num = int(position_num)
            if position_num < 1 or position_num > 10:
                flash('Кількість має бути від 1 до 10!', 'danger')
            else:
                basket = session.get('basket', {})
                basket[position_name] = str(position_num)
                session['basket'] = basket
                flash('Позицію додано до кошика!', 'success')
                return redirect(url_for('create_order'))  # Переходимо одразу у кошик
        except ValueError:
            flash('Некоректна кількість! Введіть число.', 'danger')

    with Session() as cursor:
        us_position = cursor.query(Menu).filter_by(active=True, name=name).first()
        if not us_position:
            flash('Позицію не знайдено!', 'danger')
            return redirect(url_for('menu'))
    return render_template('position.html', csrf_token=session["csrf_token"], position=us_position)

@app.route('/test_basket')
def test_basket():
    basket = session.get('basket', {})
    return basket

@app.route('/update_basket', methods=['POST'])
@login_required
def update_basket():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        return "Запит заблоковано!", 403

    basket = session.get('basket', {})
    action = request.form.get('action')
    position_name = request.form.get('position_name')

    if action == 'increase':
        current_quantity = int(basket.get(position_name, 0))
        if current_quantity < 10:
            basket[position_name] = str(current_quantity + 1)
        else:
            flash('Максимальна кількість для однієї позиції — 10!', 'warning')
    elif action == 'decrease':
        current_quantity = int(basket.get(position_name, 0))
        if current_quantity > 1:
            basket[position_name] = str(current_quantity - 1)
        else:
            flash('Мінімальна кількість для однієї позиції — 1!', 'warning')
    elif action == 'remove':
        if position_name in basket:
            del basket[position_name]
            flash('Позицію видалено з кошика!', 'success')

    session['basket'] = basket
    session.modified = True
    return redirect(url_for('create_order'))

@app.route('/create_order', methods=['GET', 'POST'])
@login_required
def create_order():
    basket = session.get('basket', {})
    basket_details = []

    if basket:
        with Session() as db_session:
            for name, quantity in basket.items():
                item = db_session.query(Menu).filter_by(name=name, active=True).first()
                if item:
                    basket_details.append({
                        'name': name,
                        'quantity': int(quantity),
                        'price': float(item.price),
                        'total': float(item.price) * int(quantity)
                    })

    if request.method == 'POST':
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Запит заблоковано!", 403

        if not current_user.is_authenticated:
            flash("Для оформлення замовлення необхідно бути зареєстрованим!", 'danger')
            return redirect(url_for('login'))
        else:
            if not basket:
                flash("Ваш кошик порожній!", 'danger')
            else:
                with Session() as db_session:
                    new_order = Orders(order_list=basket, order_time=datetime.now(), user_id=current_user.id)
                    db_session.add(new_order)
                    db_session.commit()
                    session.pop('basket', None)
                    db_session.refresh(new_order)
                    flash("Замовлення оформлено!", "success")
                    return redirect(url_for('profile'))  # Повертаємо у профіль

    return render_template('create_order.html', csrf_token=session.get("csrf_token"), basket_details=basket_details)

@app.route('/my_orders')
@login_required
def my_orders():
    with Session() as cursor:
        us_orders = cursor.query(Orders).filter_by(user_id=current_user.id).all()
        my_reservations = cursor.query(Reservation).filter_by(user_id=current_user.id).all()
    return render_template('my_orders.html', us_orders=us_orders, my_reservations=my_reservations)

@app.route("/my_order/<int:id>")
@login_required
def my_order(id):
    with Session() as cursor:
        us_order = cursor.query(Orders).filter_by(id=id).first()
        total_price = 0
        if us_order is not None and hasattr(us_order, "order_list") and us_order.order_list:
            for i, cnt in us_order.order_list.items():
                menu_item = cursor.query(Menu).filter_by(name=i).first()
                if menu_item is not None:
                    total_price += int(menu_item.price) * int(cnt)
        else:
            flash('Замовлення не знайдено!', 'danger')
            return redirect(url_for('my_orders'))
    return render_template('my_order.html', order=us_order, total_price=total_price)

@app.route("/cancel_order/<int:id>", methods=["POST"])
@login_required
def cancel_order(id):
    with Session() as cursor:
        order = cursor.query(Orders).filter_by(id=id, user_id=current_user.id).first()
        if order:
            cursor.delete(order)
            cursor.commit()
    return redirect(url_for('my_orders'))

@app.route('/reserved', methods=['GET', 'POST'])
@login_required
def reserved():
    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403

        table_type = request.form['table_type']
        reserved_time_start = request.form['time']
        user_latitude = request.form.get('latitude')
        user_longitude = request.form.get('longitude')

        # Отключаем обязательную проверку геолокации
        # if not user_longitude or not user_latitude:
        #     return 'Ви не надали інформацію про своє місцезнаходження'

        if user_longitude and user_latitude:
            user_cords = (float(user_latitude), float(user_longitude))
            distance = geodesic(MARGANETS_COORDS, user_cords).km
            if distance > KYIV_RADIUS_KM:
                return "Ви знаходитеся в зоні, недоступній для бронювання"

        with Session() as cursor:
            reserved_check = cursor.query(Reservation).filter_by(type_table=table_type).count()
            user_reserved_check = cursor.query(Reservation).filter_by(user_id=current_user.id).first()

            message = f'Бронь на {reserved_time_start} столика на {table_type} людини успішно створено!'
            table_limit = TABLE_NUM.get(table_type)
            if table_limit is not None and reserved_check < table_limit and not user_reserved_check:
                new_reserved = Reservation(type_table=table_type, time_start=reserved_time_start, user_id=current_user.id)
                cursor.add(new_reserved)
                cursor.commit()
            elif user_reserved_check:
                message = 'Можна мати лише одну активну бронь'
            else:
                message = 'На жаль, бронь такого типу стола наразі неможлива'
            return render_template('reserved.html', message=message, csrf_token=session["csrf_token"])
    return render_template('reserved.html', csrf_token=session["csrf_token"])

@app.route('/reservations_check', methods=['GET', 'POST'])
@login_required
def reservations_check():
    if current_user.nickname != 'Admin':
        return redirect(url_for('home'))


    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403


        reserv_id = request.form['reserv_id']
        with Session() as cursor:
            reservation = cursor.query(Reservation).filter_by(id=reserv_id).first()
            cursor.delete(reservation)
            cursor.commit()


    with Session() as cursor:
        all_reservations = cursor.query(Reservation).all()
        return render_template('reservations_check.html', all_reservations=all_reservations, csrf_token=session["csrf_token"])

if __name__ == "__main__":
    app.run(debug=True)

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
            if position_obj is not None:
                if 'change_status' in request.form:
                    position_obj.active = not position_obj.active
                elif 'delete_position' in request.form:
                    cursor.delete(position_obj)
                cursor.commit()
            else:
                flash('Позицію не знайдено!', 'danger')
                return redirect(url_for('menu_check'))

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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
