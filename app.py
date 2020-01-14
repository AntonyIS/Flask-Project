from flask import Flask, flash
from flask import request, redirect,url_for, render_template
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from werkzeug.utils import secure_filename
from wtforms import SubmitField
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_login import login_user, logout_user, login_required,LoginManager, UserMixin

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Top secret'
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///sokoni.sqlite" #path to db
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+ "/File_Download_Upload/static/images"
app.config["UPLOAD_FOLDER"]= BASE_DIR

db =SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100),nullable=False)
    description = db.Column(db.String(200),nullable=False)
    image = db.Column(db.String(100),nullable=True)


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100),nullable=False)
    first_name = db.Column(db.String(200),nullable=False)
    last_name = db.Column(db.String(100),nullable=False)
    email = db.Column(db.String(100),nullable=False)
    password = db.Column(db.String(100),nullable=False)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email= request.form.get('email')
        password = request.form.get('password')

        password = generate_password_hash(password)

        user = User(username=username, first_name=first_name, last_name=last_name,email=email,password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', title="Signup")


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email= request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if check_password_hash(user.password, password):
            login_user(user)
            flash(u'You were successfully logged in','alert alert-success')
            return redirect(url_for('index'))
        flash(u'Your login credentials are not correct, try again or signup','alert alert-danger')
        return redirect('/login')
    return render_template('login.html', title="Login")


@app.route('/', methods=['GET', 'POST'])
def index():
    products = Product.query.all()

    if request.form and request.files:
        # grab text data
        name = request.form.get('name')
        description = request.form.get('description')
        # grab file data
        f = request.files['imageUpload']
        filename = secure_filename(f.filename)

        image = "{}/{}/{}".format("static","images",filename)

        # image upload
        f.save(os.path.join(app.config["UPLOAD_FOLDER"] , filename))
        product = Product(name=name, description=description, image=image)
        db.session.add(product)
        db.session.commit()
        flash(u'Product uploaded successfully', 'alert alert-success')
        return redirect(url_for('index'))

    return render_template('home.html', products=products)


@app.route('/detail/<int:product_id>', )
def detail(product_id):
    product = Product.query.get(product_id)
    image = product.image
    print(image)
    return render_template('detail.html', product=product, image=image)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=3000)
