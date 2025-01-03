import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import markdown
from config import ProductionConfig, DevelopmentConfig
import logging
import re
import uuid
import bleach
from functools import wraps

# Email validation regex
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

app = Flask(__name__)

# Load configuration based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# Set a secure secret key for session management
app.secret_key = app.config['SECRET_KEY']

# Configure uploads
UPLOAD_FOLDER = os.path.join(app.instance_path, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure the instance and uploads folders exist
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
if not app.debug:
    import logging
    file_handler = logging.FileHandler('error.log')
    file_handler.setLevel(logging.ERROR)
    app.logger.addHandler(file_handler)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Roll back the session in case of database errors
    app.logger.error('Server Error: %s' % str(error))
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'unrestricted', 'admin' or 'user'
    posts = db.relationship('Post', backref=db.backref('author', lazy=True), lazy=True, foreign_keys='Post.author_id')
    comments = db.relationship('Comment', backref=db.backref('author', lazy=True), lazy=True, foreign_keys='Comment.author_id')
    
    @staticmethod
    def validate_email(email):
        return bool(EMAIL_REGEX.match(email))

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    images = db.relationship('Image', backref='post', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

@app.template_filter('markdown')
def markdown_filter(text):
    # Configure allowed HTML tags and attributes
    allowed_tags = [
        'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'br', 'hr',
        'strong', 'em', 'a', 'ul', 'ol', 'li', 'code', 'pre',
        'img', 'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'div', 'span'
    ]
    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title'],
        'pre': ['class'],
        'code': ['class'],
        '*': ['class']
    }

    try:
        # Convert markdown to HTML
        html = markdown.markdown(text, extensions=['fenced_code', 'tables'])
        
        # Process code blocks
        import re
        def replace_code_block(match):
            lang = match.group(1) or 'plaintext'
            code = match.group(2)
            return f'<pre class="language-{lang}"><code class="language-{lang}">{code}</code></pre>'
        
        # Replace code blocks with proper language classes
        html = re.sub(
            r'<pre><code class="([^"]*)">(.*?)</code></pre>',
            replace_code_block,
            html,
            flags=re.DOTALL
        )
        
        # Sanitize HTML
        clean_html = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        app.logger.debug("Markdown output: %s", clean_html)
        return clean_html
    except Exception as e:
        app.logger.error("Error in markdown filter: %s", str(e))
        return text

@app.route('/')
def home():
    try:
        posts = Post.query.order_by(Post.date.desc()).all()
        app.logger.debug("Found %d posts" % len(posts))
        return render_template('home.html', posts=posts)
    except Exception as e:
        app.logger.error("Error in home route: %s" % str(e))
        return render_template('errors/500.html'), 500

@app.route('/post/<int:post_id>')
def post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        app.logger.debug("Post found: %d, %s" % (post.id, post.title))
        app.logger.debug("Author: %s" % (post.author.username if post.author else 'No author'))
        app.logger.debug("Comments: %d" % len(post.comments))
        app.logger.debug("Images: %d" % (len(post.images) if post.images else 0))
        return render_template('post.html', post=post)
    except Exception as e:
        app.logger.error("Error in post route: %s" % str(e))
        return render_template('errors/500.html'), 500

def user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'user':
            flash('Only normal users can perform this action.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'unrestricted']:
            flash('Only administrators can perform this action.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
@user_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')
    
    if not content:
        flash('Comment cannot be empty.', 'error')
        return redirect(url_for('post', post_id=post_id))
    
    comment = Comment(
        content=content,
        author_id=current_user.id,
        post_id=post_id
    )
    
    try:
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been added!', 'success')
    except Exception as e:
        app.logger.error("Error adding comment: %s" % str(e))
        db.session.rollback()
        flash('Error adding comment. Please try again.', 'error')
    
    return redirect(url_for('post', post_id=post_id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    try:
        comment = Comment.query.get_or_404(comment_id)
        post_id = comment.post_id
        
        if comment.author != current_user and current_user.role != 'admin':
            flash('You do not have permission to delete this comment.', 'error')
            return redirect(url_for('post', post_id=post_id))
        
        db.session.delete(comment)
        db.session.commit()
        flash('Your comment has been deleted!', 'success')
        
    except Exception as e:
        app.logger.error("Error deleting comment: %s" % str(e))
        db.session.rollback()
        flash('Error deleting comment. Please try again.', 'error')
    
    return redirect(url_for('post', post_id=post_id))

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Allow unrestricted users to edit any post
    if current_user.role != 'unrestricted' and current_user.id != post.author_id:
        flash('You do not have permission to edit this post.', 'error')
        return redirect(url_for('post', post_id=post_id))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title:
            flash('Title is required!', 'error')
            return redirect(url_for('edit_post', post_id=post_id))
        
        # Update post
        post.title = title
        post.content = content
        
        # Handle new image uploads
        if 'images' in request.files:
            files = request.files.getlist('images')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = "%s_%s" % (uuid.uuid4(), filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    
                    image = Image(
                        filename=unique_filename,
                        original_filename=filename,
                        post=post
                    )
                    db.session.add(image)
        
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post_id))
    
    return render_template('edit_post.html', post=post)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Allow unrestricted users to delete any post
    if current_user.role != 'unrestricted' and current_user.id != post.author_id:
        flash('You do not have permission to delete this post.', 'error')
        return redirect(url_for('post', post_id=post_id))
    
    # Delete associated images from filesystem
    for image in post.images:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
        except Exception as e:
            app.logger.error("Error deleting image file: %s" % str(e))
    
    # Delete post and all associated comments and images
    db.session.delete(post)
    db.session.commit()
    
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/post/<int:post_id>/image/<int:image_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_image(post_id, image_id):
    image = Image.query.get_or_404(image_id)
    post = Post.query.get_or_404(post_id)
    
    # Check if user is authorized to delete this image
    if post.author != current_user:
        flash('You do not have permission to delete this image.', 'error')
        return redirect(url_for('post', post_id=post_id))
    
    # Delete image file from filesystem
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
    except Exception as e:
        app.logger.error("Error deleting image file: %s" % str(e))
    
    # Delete image record from database
    db.session.delete(image)
    db.session.commit()
    
    flash('Image has been deleted!', 'success')
    return redirect(url_for('edit_post', post_id=post_id))

@app.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title:
            flash('Title is required!')
            return redirect(url_for('create'))
        
        # Create the post first
        post = Post(title=title, content=content, author=current_user)
        db.session.add(post)
        db.session.commit()
        
        # Handle image uploads
        if 'images' in request.files:
            files = request.files.getlist('images')
            for file in files:
                if file and allowed_file(file.filename):
                    # Generate a secure filename with UUID
                    filename = secure_filename(file.filename)
                    unique_filename = "%s_%s" % (uuid.uuid4(), filename)
                    
                    # Save the file
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    
                    # Create image record
                    image = Image(
                        filename=unique_filename,
                        original_filename=filename,
                        post=post
                    )
                    db.session.add(image)
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error("Error during registration: %s" % str(e))
            flash('An error occurred during registration. Please try again.')
        
        flash('Your post has been created!')
        return redirect(url_for('post', post_id=post.id))
    
    return render_template('create.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate username
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Validate email
        if not User.validate_email(email):
            flash('Invalid email address')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Validate password
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='user'
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error('Error during registration: %s' % str(e))
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/remove-all-posts', methods=['POST'])
@login_required
@admin_required
def remove_all_posts():
    try:
        # Delete all image files from the filesystem
        images = Image.query.all()
        for image in images:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
            except Exception as e:
                app.logger.error(f"Error deleting image file {image.filename}: {str(e)}")

        # Delete all posts (this will cascade delete comments and images)
        Post.query.delete()
        db.session.commit()
        
        flash('All posts have been successfully removed!', 'success')
    except Exception as e:
        app.logger.error(f"Error removing all posts: {str(e)}")
        db.session.rollback()
        flash('An error occurred while removing posts.', 'error')
    
    return redirect(url_for('home'))

@app.route('/ads.txt')
def ads_txt():
    return send_from_directory('static', 'ads.txt')

@app.route('/<path:filename>')
def serve_root_files(filename):
    if filename.endswith('.html') or filename.endswith('.txt'):
        return send_from_directory('static', filename)
    return '', 404

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
    app.run(debug=True)
