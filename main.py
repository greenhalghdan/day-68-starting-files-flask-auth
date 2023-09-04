from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


class Newuser(FlaskForm):
    email = StringField('Post Title', validators=[DataRequired()])
    password = StringField('Subtitle', validators=[DataRequired()])
    name = StringField('Author', validators=[DataRequired()])
    submit = SubmitField('Submit')

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)
@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    new_user_form = Newuser()
    if request.method == "POST":
        usernames = db.session.execute(db.select(User)).scalars().all()
        for username in usernames:
            print(username.email + request.form.get('email'))
            if username.email != request.form.get('email'):
                flash('email address already exists.')
                print("here")
                return render_template("register.html")
        passwordh = generate_password_hash(password=request.form.get('password'), method='pbkdf2:sha256',
                                           salt_length=8)
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=passwordh
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets', user_id=new_user.id))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        print(password)
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        print("After DB call")
        print(user.password)
        print(password)
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets', user_id=user.id))
        else:
            flash('email address or password invalid.')

    print("here")
    return render_template("login.html")


@app.route('/secrets/<user_id>', methods=["GET"])
@login_required
def secrets(user_id):
    results = db.session.execute(db.select(User).where(User.id == user_id)).scalar()
    result_name = results.name
    return render_template("secrets.html", name=result_name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory("static", path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
