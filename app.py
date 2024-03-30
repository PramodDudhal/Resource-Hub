# All imports
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField 
from wtforms.validators import InputRequired, Length, EqualTo, Email
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_mail import Mail, Message
import sqlite3
import random
import logging
import os



# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



# Creating the "app" & database & uploads folder
app = Flask(__name__)
app.secret_key = "thisisasecretkey"
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'pramodadudhal521@gmail.com'
app.config['MAIL_PASSWORD'] = 'fkoy zlql ftif izrs'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)



# Login things
login_manager = LoginManager()
login_manager.init_app(app)

otp_store = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# User & Resource class which will help to store the user & files
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500))
    year_of_studying = db.Column(db.String(10))
    branch_of_study = db.Column(db.String(100))
    subject = db.Column(db.String(100))
    resource_type = db.Column(db.String(50))
    file_path = db.Column(db.String(200))
    upload_date = db.Column(db.DateTime, default=datetime.now)
    user_username = db.Column(db.Integer, db.ForeignKey('user.username'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    user_type = db.Column(db.String(10))
    resources = db.relationship('Resource', backref="user")
    posts = db.relationship('Post', backref="user", passive_deletes=True)



# Posts & Comment Class helps with doubt forum
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    comments = db.relationship('Comment', backref='post', passive_deletes=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete="CASCADE"), nullable=False)



# Clases which has help in sign up and login
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    username = StringField('Username (College Email)', validators=[InputRequired(), Length(min=6, max=50)])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    user_type = SelectField('User Type', choices=[('student', 'Student'), ('teacher', 'Teacher')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username (College Email)', validators=[InputRequired(), Length(min=6, max=50)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    message = db.Column(db.Text)



# index page route
@app.route("/")
def index():
    return render_template('index.html')



# Login routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Get the username and password from the form
        username = form.username.data
        password = form.password.data
        
        # Query the database for the user with the provided username
        user = User.query.filter_by(username=username).first()
        
        # Check if a user with the provided username exists and the password is correct
        if user and user.password == password:
            # If the credentials are valid, log the user in
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            # If the credentials are invalid, show an error message
            flash('Invalid username or password', 'error')
    
    # If the form is not submitted or validation fails, render the login template
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        # If the username is unique, proceed with user registration
       
        new_user = User(name=form.name.data,
                        username=form.username.data,
                        password=form.password.data,
                        user_type=form.user_type.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'error')
    return redirect(url_for('login'))

# Upload and view routes
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        year_of_studying = request.form['year']
        branch_of_study = request.form['branch']
        subject = request.form['subject']
        resource_type = request.form['type']
        title = request.form['title']
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            # Create the directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        
            # Check if the user is authenticated
            if current_user.is_authenticated:
                user_username = current_user.username
            else:
                flash('You must be logged in to upload resources.', 'error')
                return redirect(url_for('login'))  # Redirect to login page if user is not logged in
        
            new_resource = Resource(
                user_username=user_username,
                year_of_studying=year_of_studying,
                branch_of_study=branch_of_study,
                subject=subject,
                resource_type=resource_type,
                title = title,
                file_path=file_path
            )
        
            db.session.add(new_resource)
            db.session.commit()
        
            return redirect(url_for('index'))
    
    return render_template('upload.html')

@app.route('/select')
def select():
    return render_template('select.html')

@app.route('/view', methods=['POST'])
@login_required
def view():
    year = request.form.get('year')
    branch = request.form.get('branch')
    subject = request.form.get('subject')
    type = request.form.get('type')
    files = Resource.query.filter_by(year_of_studying=year, branch_of_study=branch, subject=subject, resource_type=type).all()
    return render_template('view.html', files=files)

@app.route('/uploads/<path:filename>')
@login_required
def view_file(filename):
    uploads_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    file_path = os.path.join(uploads_dir, filename)
    return send_file(file_path, as_attachment=False)



# Users app.routes
@app.route('/users')
@login_required
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return f'User with ID {user_id} deleted successfully.', 200  # HTTP status code 200 for success
    else:
        return f'User with ID {user_id} not found.', 404  # HTTP status code 404 for not found



# Posts app.routes
@app.route("/posts")
@login_required
def posts():
    posts = Post.query.all()
    user_id = current_user.id if current_user.is_authenticated else None
    return render_template("post_div.html", author_id=user_id, posts=posts)

@app.route("/create-post", methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == "POST":
        text = request.form.get('text')

        if not text:
            flash('Post cannot be empty', category='error')
        else:
            if current_user.is_authenticated:  # Check if user is authenticated
                post = Post(text=text, author_id=current_user.id)
                db.session.add(post)
                db.session.commit()
                flash('Post created!', category='success')
                return redirect(url_for('posts'))
            else:
                # Handle the case where the user is not authenticated
                flash('You need to log in to create a post', category='error')
                return redirect(url_for('login'))

    return render_template('create_post.html', author=current_user)

@app.route("/delete-post/<id>")
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    try:
        db.session.delete(post)
        db.session.commit()
        flash("Post was deleted")
        posts = Post.query.all()
        return render_template("post_div.html", author = current_user, posts=posts)
    except:
        flash("There was an error while deleting the post, try again")
        posts = Post.query.all()
        return render_template("post_div.html", author = current_user, posts=posts)
    # if not post:
    #     flash("Post does not exist.", category='error')
    # elif current_user.id != post.author_id:
    #     flash('You do not have permission to delete this post.', category='error')
    # else:
    #     db.session.delete(post)
    #     db.session.commit()
    #     flash('Post deleted.', category='success')

    # return redirect(url_for('posts'))

@app.route("/create-comment/<post_id>", methods=['POST'])
@login_required
def create_comment(post_id):
    text = request.form.get('text')

    if not text:
        flash('Comment cannot be empty.', category='error')
    else:
        post = Post.query.filter_by(id=post_id).first()
        if post:
            comment = Comment(
                text=text, user_id=current_user.id, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
        else:
            flash('Post does not exist.', category='error')

    return redirect(url_for('posts'))

@app.route("/delete-comment/<comment_id>")
@login_required
def delete_comment(comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()

    if not comment:
        flash('Comment does not exist.', category='error')
    elif current_user.id != comment.user_id and current_user.id != comment.post.user_id:
        flash('You do not have permission to delete this comment.', category='error')
    else:
        db.session.delete(comment)
        db.session.commit()

    return redirect(url_for('posts'))



# Additional routes...
@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html')

@app.route("/categorize")
@login_required
def categorize():
    return render_template("categorize.html")

@app.route("/aboutus")
@login_required
def about():
    return render_template("aboutus.html")

@app.route("/firstyear")
@login_required
def firstyear():
    return render_template("firstyear.html")

@app.route("/secondyear")
@login_required
def secondyear():
    return render_template("secondyear.html")

@app.route("/thirdyear")
@login_required
def thirdyear():
    return render_template("thirdyear.html")

@app.route("/fourthyear")
@login_required
def fourthyear():
    return render_template("fourthyear.html")

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        if email not in otp_store:
            otp = generate_otp()
            otp_store[email] = otp
        else:
            otp = otp_store[email]
        # Here you would send the OTP to the user's email
        send_otp_email(email, otp)
        flash('An OTP has been sent to your email address.', 'success')
        return redirect(url_for('verify_otp', email=email))
    return render_template('forgot_password.html')

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    msg = Message('OTP for Password Reset', sender='your_email@example.com', recipients=[email])
    msg.body = f'Your OTP for password reset is: {otp}'
    mail.send(msg)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == otp_store[email]:
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_otp.html', email=email)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        # Here you would retrieve the old password from your database using the email address
        # and then send it to the user's email address
        old_password = get_old_password(email)
        send_old_password_email(email, old_password)
        flash('Your old password has been sent to your email address.', 'success')
        return redirect(url_for('index'))
    return render_template('reset_password.html', email=email)

def get_old_password(username):
    try:
        # Connect to the database
        conn = sqlite3.connect('instance/data.db')
        cursor = conn.cursor()

        # Query the database for the hashed password
        query = "SELECT password FROM user WHERE username = ?"
        cursor.execute(query, (username,))
        row = cursor.fetchone()

        # If the username exists in the database
        if row:
           
            # Compare the hashed input password with the hashed password from the database
            return row[0]
            # Return True if passwords match, False otherwise
        else:
            return False  # Username not found

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        # Close the database connection
        if conn:
            conn.close()

def send_old_password_email(email, old_password):
    msg = Message('Your Old Password', sender='your_email@example.com', recipients=[email])
    msg.body = f'Your old password is: {old_password}'
    mail.send(msg)

def send_reset_password_email(email):
    msg = Message('Password Reset Request', sender='your_email@example.com', recipients=[email])
    msg.body = f'''To reset your password, please click on the following link:
{url_for('reset_password', _external=True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Save the feedback to the database
        new_feedback = Feedback(name=name, email=email, message=message)
        db.session.add(new_feedback)
        db.session.commit()
        
        return 'Thank you for your feedback!'
    return render_template('contact.html')



@app.route("/testimonials")
@login_required
def testimonials():
    return render_template("testimonials.html")

@app.route("/FAQ")
@login_required
def FAQ():
    return render_template("FAQ.html")

@app.route("/privacy")
@login_required
def privacy():
    return render_template("privacy.html")



# Internal error handlers
@app.errorhandler(401)
def page_not_found(e):
	return render_template("401.html"), 401



# Database creation and running
def create_database():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_database()
    app.run(debug=True)