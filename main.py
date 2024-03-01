from flask import Flask, render_template, url_for, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash  
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
bootstrap = Bootstrap5(app)
app.config['SECRET_KEY'] = 'your_secret_key'

login_manager = LoginManager()
login_manager.login_view = 'login'

db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)
login_manager.init_app(app)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

with app.app_context():
    db.create_all()

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("index.html" , is_authenticated=current_user.is_authenticated)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/physics")
def physics():
    return render_template("physics.html" , is_authenticated=current_user.is_authenticated)

@app.route("/maths")
def maths():
    return render_template("maths.html" , is_authenticated=current_user.is_authenticated)

@app.route("/business")
def business():
    return render_template("business.html" , is_authenticated=current_user.is_authenticated)

@app.route("/physcology")
def physcology():
    return render_template("physcology.html" , is_authenticated=current_user.is_authenticated)

@app.route("/cs")
def cs():
    return render_template("cs.html" , is_authenticated=current_user.is_authenticated)

@app.route("/shop")
def shop():
    return render_template("shop.html" , is_authenticated=current_user.is_authenticated)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html', form=form, is_authenticated=current_user.is_authenticated)


@app.route("/register",methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(name=form.name.data, email=form.email.data, password=hash_and_salted_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template("register.html" , form=form)


@app.route("/cart")
def cart():
    print(current_user.is_authenticated)
    return render_template("cart.html", is_authenticated=current_user.is_authenticated)

@login_required
@app.route("/checkout")
def checkout():
    return render_template("checkout.html")

@login_required
@app.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)