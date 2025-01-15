from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import app, db

def upgrade():
    with app.app_context():
        # Add timer_active column to course table
        db.session.execute('ALTER TABLE course ADD COLUMN timer_active BOOLEAN DEFAULT FALSE')
        db.session.commit()

def downgrade():
    with app.app_context():
        # Remove timer_active column from course table
        db.session.execute('ALTER TABLE course DROP COLUMN timer_active')
        db.session.commit()

if __name__ == '__main__':
    upgrade()
