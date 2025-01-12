from app import app, db, User, ExamSettings

def create_user(username, password, is_teacher=False):
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User {username} already exists!")
            return False

        try:
            # Create new user using the User model's set_password method
            new_user = User(username=username, is_teacher=is_teacher)
            new_user.set_password(password)
            
            # Add to database
            db.session.add(new_user)
            db.session.commit()
            print(f"Successfully created user: {username}")
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            db.session.rollback()
            return False

def main():
    print("\nWelcome to User Creation Tool")
    print("-----------------------------")
    
    # Initialize database
    with app.app_context():
        try:
            # Create all tables if they don't exist
            db.create_all()
            
            # Create default exam settings if not exists
            if not ExamSettings.query.first():
                default_settings = ExamSettings(active_day=1)
                db.session.add(default_settings)
                db.session.commit()
                print("Created default exam settings.")
        except Exception as e:
            print(f"Database initialization error: {e}")
            return
    
    while True:
        print("\n1. Create Single Student")
        print("2. Create Single Teacher")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")
        
        if choice == "3":
            break
            
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        if choice == "1":
            success = create_user(username, password, is_teacher=False)
        elif choice == "2":
            success = create_user(username, password, is_teacher=True)
        
        if success:
            print("User created successfully!")
        else:
            print("Failed to create user.")

if __name__ == "__main__":
    main()
