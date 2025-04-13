import os
from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, 
    create_access_token, 
    jwt_required, 
    get_jwt_identity, 
    unset_jwt_cookies,
    set_access_cookies
)
from models import db, User, Book
from dotenv import load_dotenv
from collections import Counter
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev")
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_SECRET_KEY'] = os.getenv("SECRET_KEY", "dev")
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Отключаем CSRF для JWT
app.config['WTF_CSRF_ENABLED'] = True  # Включаем CSRF для форм
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


db.init_app(app)
jwt = JWTManager(app)
csrf = CSRFProtect(app)

@app.after_request
def inject_csrf_token(response):
    # Устанавливаем CSRF токен в куки и в заголовки
    csrf_token = generate_csrf()
    response.set_cookie('csrf_token', csrf_token)
    return response

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        # Проверка на существование пользователя с таким именем
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует.', 'error')
            return redirect(url_for('register'))
        
        # Создаем нового пользователя, если имя свободно
        user = User(username=username)
        if username == "admin":
            user.set_admin_status()
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрированы!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            access_token = create_access_token(identity=str(user.id))
            resp = make_response(redirect(url_for('books')))
            set_access_cookies(resp, access_token)
            return resp
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp


@app.route('/books')
@jwt_required()
def books():
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)
    
    # Если админ смотрит другого пользователя
    view_user_id = request.args.get('user_id')
    if current_user.is_admin and current_user.username == 'admin' and view_user_id:
        user_id = view_user_id
    page = int(request.args.get('page', 1))
    per_page = 5
    
    # Фильтрация
    status_filter = request.args.get('status_filter')
    min_rating = request.args.get('min_rating')
    title_filter = request.args.get('title_filter')
    author_filter = request.args.get('author_filter')
    query = Book.query.filter_by(user_id=user_id)
    
    if title_filter:
        query = query.filter(Book.title.ilike(f'%{title_filter}%'))
    if author_filter:
        query = query.filter(Book.author.ilike(f'%{author_filter}%'))
    if status_filter:
        query = query.filter_by(status=status_filter)
    if min_rating:
        query = query.filter(Book.rating >= int(min_rating))
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    view_user = User.query.get(user_id)
    
    return render_template('books.html', 
                         books=pagination, 
                         current_user=current_user,
                         view_user=view_user)

@app.route('/add_book', methods=['POST'])
@jwt_required()
def add_book():
    user_id = get_jwt_identity()
    new_book = Book(
        title=request.form['title'],
        author=request.form['author'],
        status=request.form['status'],
        rating=int(request.form['rating']),
        user_id=user_id
    )
    db.session.add(new_book)
    db.session.commit()
    return redirect(url_for('books'))

@app.route('/update_book/<int:book_id>', methods=['POST'])
@jwt_required()
def update_book(book_id):
    book = Book.query.get_or_404(book_id)
    if str(book.user_id) != get_jwt_identity():
        abort(403)
    
    book.title = request.form['title']
    book.author = request.form['author']
    book.status = request.form['status']
    book.rating = int(request.form['rating'])
    db.session.commit()
    return redirect(url_for('books'))

@app.route('/delete_book/<int:book_id>', methods=['POST'])
@jwt_required()
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if str(book.user_id) != get_jwt_identity():
        abort(403)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('books'))

@app.route('/update_status/<int:book_id>', methods=['POST'])
@jwt_required()
def update_status(book_id):
    book = Book.query.get_or_404(book_id)
    if str(book.user_id) != get_jwt_identity():
        abort(403)
    new_status = request.form.get('status')
    if new_status in ['Не прочитана', 'В процессе', 'Прочитана']:
        book.status = new_status
        db.session.commit()
    return redirect(url_for('books', page=request.args.get('page', 1)))

@app.route("/stats")
@jwt_required()
def stats():
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)
    view_user_id = request.args.get('user_id')
    if current_user.is_admin and current_user.username == 'admin' and view_user_id:
        user_id = view_user_id
    books = Book.query.filter_by(user_id=user_id).all()

    total_books = len(books)
    completed_books = sum(1 for b in books if b.status == 'Прочитана')
    in_progress_books = sum(1 for b in books if b.status == 'В процессе')
    uncompleted_books = sum(1 for b in books if b.status == 'Не прочитана')

    try:
        completion_percentage = round((completed_books / total_books) * 100, 1)
    except ZeroDivisionError:
        completion_percentage = 0.0

    ratings = [b.rating for b in books if b.rating]
    avg_rating = round(sum(ratings) / len(ratings), 1) if ratings else '—'

    authors = [b.author for b in books if b.author]
    top_author = Counter(authors).most_common(1)[0][0] if authors else '—'

    # распределение оценок от 1 до 10
    rating_distribution = [0] * 10
    for r in ratings:
        if 1 <= r <= 10:
            rating_distribution[int(r) - 1] += 1

    stats_data = {
        'total_books': total_books,
        'completed_books': completed_books,
        'in_progress_books': in_progress_books,
        'uncompleted_books': uncompleted_books,
        'completion_percentage': completion_percentage,
        'avg_rating': avg_rating,
        'top_author': top_author,
        'rating_distribution': rating_distribution
    }

    view_user = User.query.get(user_id)
    return render_template('stats.html', 
                            stats=stats_data, 
                            current_user=current_user,
                            view_user=view_user)

@app.route('/settings', methods=['GET', 'POST'])
@jwt_required()
def settings():
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)

    if request.method == 'POST':
        # Обычная обработка формы настроек
        username = request.form['username']
        password = request.form['password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not current_user.check_password(password):
            flash('Неверный текущий пароль.', 'error')
            return redirect(url_for('settings'))

        if new_password and new_password != confirm_password:
            flash('Новый пароль и подтверждение пароля не совпадают.', 'error')
            return redirect(url_for('settings'))

        if username != current_user.username:
            if User.query.filter(User.username == username).first():
                flash('Этот логин уже занят.', 'error')
                return redirect(url_for('settings'))
            current_user.username = username

        if new_password:
            current_user.set_password(new_password)

        db.session.commit()
        flash('Профиль успешно обновлен!', 'success')
        return redirect(url_for('settings'))

    # Для админа - получаем список всех пользователей
    users = []
    if current_user.username == 'admin' and current_user.is_admin:
        users = User.query.filter(User.username != 'admin').all()

    return render_template('settings.html', current_user=current_user, users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
