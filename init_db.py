from __future__ import print_function
from app import app, db, User, Post, Comment
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin'),
                role='admin'
            )
            db.session.add(admin)
            try:
                db.session.commit()
            except Exception as e:
                print("Error creating admin user: %s" % str(e))
                db.session.rollback()
                return
        
        # Create sample post
        sample_post = Post(
            title='Welcome to Tweaker Blog',
            content='''
# Welcome to Tweaker Blog!

This is a sample post to demonstrate the features of our blog platform.

## Features:

1. Markdown Support
2. Code Highlighting
```python
def hello_world():
    print("Hello, World!")
```
3. Image Galleries
4. Comments System

Feel free to explore and create your own posts!
            ''',
            author_id=1,
            date=datetime.utcnow()
        )
        db.session.add(sample_post)
        
        try:
            db.session.commit()
            print("Database initialized successfully!")
        except Exception as e:
            print("Error initializing database: %s" % str(e))
            db.session.rollback()

if __name__ == '__main__':
    init_db()
