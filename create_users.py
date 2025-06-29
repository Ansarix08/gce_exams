from app import app, db, User, ExamSettings

def create_user(username, password, is_teacher=False):
    with app.app_context():
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User {username} already exists!")
            return False
        try:
            new_user = User(username=username, is_teacher=is_teacher)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            print(f"Successfully created user: {username}")
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            db.session.rollback()
            return False

def view_teachers():
    with app.app_context():
        teachers = User.query.filter_by(is_teacher=True).all()
        if not teachers:
            print("No teachers found.")
            return
        print("\n--- List of Teachers ---")
        for teacher in teachers:
            status = "Active" if teacher.is_active else "Deactivated"
            print(f"Username: {teacher.username}, Status: {status}")
        print("------------------------")

def delete_teacher():
    username = input("Enter the username of the teacher to delete: ")
    with app.app_context():
        teacher = User.query.filter_by(username=username, is_teacher=True).first()
        if not teacher:
            print(f"Teacher '{username}' not found.")
            return
        
        confirm = input(f"Are you sure you want to delete teacher '{username}'? (y/n): ")
        if confirm.lower() == 'y':
            try:
                db.session.delete(teacher)
                db.session.commit()
                print(f"Teacher '{username}' deleted successfully.")
            except Exception as e:
                db.session.rollback()
                print(f"Error deleting teacher: {e}")
        else:
            print("Deletion cancelled.")

def toggle_teacher_status():
    username = input("Enter the username of the teacher to activate/deactivate: ")
    with app.app_context():
        teacher = User.query.filter_by(username=username, is_teacher=True).first()
        if not teacher:
            print(f"Teacher '{username}' not found.")
            return

        teacher.is_active = not teacher.is_active
        try:
            db.session.commit()
            status = "activated" if teacher.is_active else "deactivated"
            print(f"Teacher '{username}' has been {status}.")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating teacher status: {e}")

def main():
    print("\nWelcome to User Creation and Management Tool")
    print("--------------------------------------------")
    
    with app.app_context():
        try:
            db.create_all()
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
        print("3. View Teachers")
        print("4. Activate/Deactivate a Teacher")
        print("5. Delete a Teacher")
        print("6. Exit")
        choice = input("Enter your choice (1-6): ")
        
        if choice == '1' or choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            is_teacher = (choice == '2')
            success = create_user(username, password, is_teacher=is_teacher)
            if success:
                print("User created successfully!")
            else:
                print("Failed to create user.")
        elif choice == '3':
            view_teachers()
        elif choice == '4':
            toggle_teacher_status()
        elif choice == '5':
            delete_teacher()
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
