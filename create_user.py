from app import app, db, User
import sys
from werkzeug.security import generate_password_hash
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def create_user(username, email, password, role='user'):
    with app.app_context():
        db.create_all()
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print("User {} already exists!".format(username))
            return
            
        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print("Email {} is already registered!".format(email))
            return
            
        # Validate email format
        if not EMAIL_REGEX.match(email):
            print("Invalid email format!")
            return
        
        # Create new user with hashed password
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role
        )
        db.session.add(user)
        db.session.commit()
        print("{} user {} created successfully!".format(role.capitalize(), username))

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python create_user.py <username> <email> <password> [role]")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    password = sys.argv[3]
    role = sys.argv[4] if len(sys.argv) > 4 else 'user'
    
    if role not in ['unrestricted', 'admin', 'user']:
        print("Role must be either 'unrestricted', 'admin' or 'user'")
        sys.exit(1)
    
    create_user(username, email, password, role)
