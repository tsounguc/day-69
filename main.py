from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)

login_manager.init_app(app)


# User table for all registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # author = db.Column(db.String(250), nullable=False)
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates='posts')
    img_url = db.Column(db.String(250), nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, ForeignKey("users.id"))







with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        user = db.get_or_404(User, user_id)
    return user


def check_user_access():
    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.id == 1
    return is_admin


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if check_user_access():
            return function(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        with app.app_context():
            # Use Werkzeug to hash the user's password when creating a new user.
            user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
            if user:
                flash("You've already signed up with that email. Log in instead")
                return redirect(url_for('login'))
            else:
                password_hash = generate_password_hash(password=form.password.data, method='pbkdf2', salt_length=8)
                user = User(email=form.email.data, password=password_hash, name=form.name.data)
                db.session.add(user)
                db.session.commit()

                user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()

                login_user(user)
                return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Retrieve a user from the database based on their email.
    form = LoginForm()
    if form.validate_on_submit():
        with app.app_context():
            user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
            if not user:
                flash("That email does not exist, please try again.")
                return redirect(url_for('login'))
            elif not check_password_hash(pwhash=user.password, password=form.password.data):
                flash("Password incorrect, please try again.")
                return redirect(url_for('login'))
            else:
                login_user(user)
                return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()

    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated,
                           is_admin=check_user_access())


# Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           is_admin=check_user_access())


# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
