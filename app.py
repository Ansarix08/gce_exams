from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import os
import secrets
from contextlib import contextmanager
from typing import Dict, List
from sqlalchemy import inspect
import pandas as pd
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///exam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'csrf-secret-key'  # Change this to a secure secret key
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Login Form Class
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_teacher = db.Column(db.Boolean, default=False)
    answers = db.relationship('Answer', backref='user', lazy=True)
    absences = db.relationship('ExamAbsence', backref='user', lazy=True)
    question_selections = db.relationship('QuestionSelection', backref='student', lazy=True)
    enrolled_courses = db.relationship('Course', secondary='student_course', backref=db.backref('enrolled_students', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class StudentCourse(db.Model):
    __tablename__ = 'student_course'
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), primary_key=True)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)

class CourseCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)  # e.g., 'DCA', 'PGDCA'
    description = db.Column(db.String(200))
    courses = db.relationship('Course', backref='category', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    category_id = db.Column(db.Integer, db.ForeignKey('course_category.id'), nullable=False)
    questions = db.relationship('Question', backref='course', lazy=True)
    timer = db.relationship('ExamTimer', backref='course', uselist=False)
    timer_active = db.Column(db.Boolean, default=False)

class ExamTimer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_time = db.Column(db.DateTime, nullable=True)  # When the exam started
    end_time = db.Column(db.DateTime, nullable=True)    # When the exam should end

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    day = db.Column(db.Integer, nullable=False, default=1)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)
    answers = db.relationship('Answer', backref='question', lazy=True)
    student_selections = db.relationship('QuestionSelection', backref='selected_question', lazy=True)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_answer = db.Column(db.String(1), nullable=False)
    selection_date = db.Column(db.Date, nullable=False, default=date.today)
    day = db.Column(db.Integer, nullable=False)  # Added day field
    __table_args__ = (db.UniqueConstraint('user_id', 'question_id', 'day', name='unique_user_question_day'),)

class QuestionSelection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selection_date = db.Column(db.Date, nullable=False, default=date.today)
    completed = db.Column(db.Boolean, default=False)

class ExamAbsence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    marked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ExamSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active_day = db.Column(db.Integer, nullable=False, default=1)
    start_question_id = db.Column(db.Integer, nullable=False, default=1)
    end_question_id = db.Column(db.Integer, nullable=False, default=999999)

class ExamSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_date = db.Column(db.Date, nullable=False, default=date.today)
    day = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Add a function to handle errors and exceptions
def handle_error(error):
    db.session.rollback()
    flash(f'An error occurred: {str(error)}', 'error')
    print(f"Error: {str(error)}")

# Use a decorator to handle errors in all routes
def error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            handle_error(e)
            return redirect(url_for('index'))
    return wrapper

# Use a context manager to handle database transactions
@contextmanager
def db_transaction():
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        handle_error(e)
        pass  

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_teacher:
            return redirect(url_for('teacher_dashboard'))
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            
            if user.is_teacher:
                flash('Welcome Teacher!', 'success')
                return redirect(url_for('teacher_dashboard'))
            
            # Student login logic
            settings = ExamSettings.query.first()
            if not settings:
                settings = ExamSettings(active_day=1)
                db.session.add(settings)
                db.session.commit()
            
            # Check if student has already submitted exam for today
            exam_submitted = ExamSubmission.query.filter_by(
                user_id=user.id,
                day=settings.active_day,
                submission_date=date.today()
            ).first()
            
            if exam_submitted:
                flash('You have already submitted your exam for today. Please come back tomorrow.', 'info')
                return redirect(url_for('logout'))
            
            # Check if student has completed today's exam
            today_answers = Answer.query.filter_by(
                user_id=user.id,
                selection_date=date.today()
            ).all()
            
            if len(today_answers) == 0:
                flash(f'Welcome to Day {settings.active_day} exam!', 'success')
            
            return redirect(url_for('exam'))
            
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/exam')
@login_required
def exam():
    if current_user.is_teacher:
        flash('Teachers cannot take exams!', 'error')
        return redirect(url_for('index'))

    settings = ExamSettings.query.first()
    if not settings:
        flash('Exam settings not configured!', 'error')
        return redirect(url_for('index'))

    # Check if exam has been submitted for today
    exam_submitted = ExamSubmission.query.filter_by(
        user_id=current_user.id,
        day=settings.active_day,
        submission_date=date.today()
    ).first()

    if exam_submitted:
        flash('You have already submitted the exam for today. Please come back tomorrow.', 'warning')
        return redirect(url_for('index'))

    # Get questions for today
    questions = Question.query.join(Course).join(
        StudentCourse, Course.id == StudentCourse.course_id
    ).filter(
        Question.day == settings.active_day,
        StudentCourse.student_id == current_user.id
    ).all()
    if not questions:
        flash('No questions available for today!', 'info')
        return redirect(url_for('index'))

    # Get course timers and activate them if needed
    current_time = datetime.utcnow()
    course_timers = {}
    for course in current_user.enrolled_courses:
        if course.timer:
            # Activate timer if not already active
            if not course.timer_active:
                course.timer_active = True
                course.timer.start_time = current_time
                course.timer.end_time = current_time + timedelta(minutes=course.timer.duration_minutes)
                db.session.add(course)
            
            course_timers[str(course.id)] = {
                'name': course.name,
                'duration_minutes': course.timer.duration_minutes,
                'active': course.timer_active,
                'start_time': course.timer.start_time.isoformat() if course.timer.start_time else None,
                'end_time': course.timer.end_time.isoformat() if course.timer.end_time else None
            }
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('Error activating exam timer', 'error')
        return redirect(url_for('index'))

    return render_template('exam.html',
                         questions=questions,
                         settings=settings,
                         course_timers=course_timers,
                         server_time=current_time.isoformat(),
                         get_answer=get_answer,
                         exam_submitted=False)  # Since we redirect if submitted, this is always False

@app.route('/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    if current_user.is_teacher:
        flash('Teachers cannot submit answers!', 'error')
        return redirect(url_for('index'))

    # Get form data
    question_id = request.form.get('question_id')
    selected_answer = request.form.get('answer')

    if not question_id or not selected_answer:
        flash('Please select an answer before submitting.', 'error')
        return redirect(url_for('exam'))

    # Get exam settings
    settings = ExamSettings.query.first()
    if not settings:
        flash('Exam settings not configured!', 'error')
        return redirect(url_for('index'))

    # Check if exam has already been submitted today
    exam_submitted = ExamSubmission.query.filter_by(
        user_id=current_user.id,
        day=settings.active_day,
        submission_date=date.today()
    ).first()

    if exam_submitted:
        flash('You have already submitted the exam for today. Please come back tomorrow.', 'warning')
        return redirect(url_for('index'))

    # Check if the user has already answered this question today
    existing_answer = get_answer(current_user.id, question_id)
    if existing_answer:
        flash('You have already answered this question. Redirecting to edit.', 'info')
        return redirect(url_for('edit_answer', question_id=question_id, answer=selected_answer))

    # Get the question to verify it exists and belongs to an active course
    question = Question.query.get(question_id)
    if not question:
        flash('Question not found!', 'error')
        return redirect(url_for('exam'))

    # Check if the course timer is active and not expired
    course = question.course
    if not course:
        flash('Question does not belong to any course!', 'error')
        return redirect(url_for('exam'))

    if not course.timer_active:
        # Try to activate the timer
        if course.timer:
            current_time = datetime.utcnow()
            course.timer_active = True
            course.timer.start_time = current_time
            course.timer.end_time = current_time + timedelta(minutes=course.timer.duration_minutes)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash('Error activating exam timer', 'error')
                return redirect(url_for('exam'))
        else:
            flash('This exam is not currently active!', 'error')
            return redirect(url_for('exam'))

    if check_timer_expired(course):
        flash('The exam timer has expired!', 'error')
        return redirect(url_for('exam'))

    # Create new answer
    try:
        answer = Answer(
            user_id=current_user.id,
            question_id=question_id,
            selected_answer=selected_answer,
            selection_date=date.today(),
            day=settings.active_day
        )
        db.session.add(answer)
        db.session.commit()
        
        # Store the current question ID in the session
        session['last_question_id'] = question_id
        
        flash('Answer submitted successfully!', 'success')
        return redirect(url_for('exam', _anchor=f'question_{question_id}'))
        
    except Exception as e:
        db.session.rollback()
        flash('Error submitting answer. Please try again.', 'error')
        print(f"Error submitting answer: {str(e)}")
        return redirect(url_for('exam', _anchor=f'question_{question_id}'))

@app.route('/submit_exam', methods=['POST'])
@login_required
def submit_exam():
    if current_user.is_teacher:
        flash('Teachers cannot submit exams!', 'error')
        return redirect(url_for('index'))

    settings = ExamSettings.query.first()
    if not settings:
        flash('Exam settings not configured!', 'error')
        return redirect(url_for('index'))

    # Check if exam has already been submitted today
    existing_submission = ExamSubmission.query.filter_by(
        user_id=current_user.id,
        day=settings.active_day,
        submission_date=date.today()
    ).first()

    if existing_submission:
        flash('You have already submitted the exam for today. Please come back tomorrow.', 'warning')
        return redirect(url_for('index'))

    # Create new exam submission
    submission = ExamSubmission(
        user_id=current_user.id,
        day=settings.active_day,
        submission_date=date.today()
    )

    try:
        db.session.add(submission)
        db.session.commit()
        flash('Exam submitted successfully! Your answers have been recorded.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error submitting exam. Please try again.', 'error')
        print(f"Error submitting exam: {str(e)}")

    return redirect(url_for('index'))

@app.route('/exam_complete')
@login_required
def exam_complete():
    if current_user.is_teacher:
        flash('Teachers cannot view exam completion page!', 'error')
        return redirect(url_for('index'))
        
    settings = ExamSettings.query.first()
    if not settings:
        return redirect(url_for('index'))
    
    return render_template('exam_complete.html', day=settings.active_day)

@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if not current_user.is_teacher:
        flash('Access denied. Teacher privileges required.', 'error')
        return redirect(url_for('index'))
        
    categories = CourseCategory.query.all()
    courses = Course.query.all()
    questions = Question.query.all()
    students = User.query.filter_by(is_teacher=False).all()
    settings = ExamSettings.query.first()
    
    if not settings:
        settings = ExamSettings(active_day=1)
        db.session.add(settings)
        db.session.commit()

    # Get all answers with their related data
    answers = Answer.query.join(User).join(Question).order_by(Answer.selection_date.desc()).all()

    # Get all course timers
    course_timers = {}
    for course in courses:
        if course.timer:
            course_timers[course.id] = {
                'duration_minutes': course.timer.duration_minutes,
                'is_active': course.timer_active
            }
    
    return render_template(
        'teacher_dashboard.html',
        categories=categories,
        courses=courses,
        questions=questions,
        students=students,
        settings=settings,
        answers=answers,
        course_timers=course_timers,
        Question=Question,
        Answer=Answer,
        StudentCourse=StudentCourse,
        active_day=settings.active_day
    )

@app.route('/teacher/category/add', methods=['POST'])
@login_required
def add_category():
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    try:
        name = request.form.get('category_name')
        description = request.form.get('category_description')
        
        if not name:
            flash('Category name is required!', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Check if category already exists
        existing_category = CourseCategory.query.filter_by(name=name).first()
        if existing_category:
            flash('A category with this name already exists!', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Create new category
        category = CourseCategory(name=name, description=description)
        db.session.add(category)
        db.session.commit()
        
        flash('Course category added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding category: {str(e)}', 'error')
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/course/add', methods=['POST'])
@login_required
def add_course():
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    course_name = request.form.get('course_name')
    category_id = request.form.get('category_id')
    
    if not all([course_name, category_id]):
        flash('Course name and category are required!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Check if course already exists
    existing_course = Course.query.filter_by(name=course_name).first()
    if existing_course:
        flash('A course with this name already exists!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Verify category exists
    category = CourseCategory.query.get(category_id)
    if not category:
        flash('Selected category does not exist!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Create new course
    new_course = Course(name=course_name, category_id=category_id)
    db.session.add(new_course)
    db.session.commit()
    
    flash('Course added successfully!', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/question/add', methods=['POST'])
@login_required
@csrf.exempt
def add_question():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        # Get form data
        course_id = request.form.get('course_id')
        question_text = request.form.get('question_text')
        option_a = request.form.get('option_a')
        option_b = request.form.get('option_b')
        option_c = request.form.get('option_c')
        option_d = request.form.get('option_d')
        correct_answer = request.form.get('correct_answer')
        day = request.form.get('day')
        
        # Validate required fields
        if not all([course_id, question_text, option_a, option_b, option_c, option_d, correct_answer, day]):
            return jsonify({
                'success': False,
                'message': 'All fields are required'
            }), 400
            
        # Validate course exists
        course = Course.query.get(course_id)
        if not course:
            return jsonify({
                'success': False,
                'message': 'Selected course does not exist'
            }), 400
            
        # Validate correct answer
        if correct_answer not in ['A', 'B', 'C', 'D']:
            return jsonify({
                'success': False,
                'message': 'Invalid correct answer'
            }), 400
            
        # Validate day
        try:
            day = int(day)
            if day < 1 or day > 6:
                return jsonify({
                    'success': False,
                    'message': 'Day must be between 1 and 6'
                }), 400
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid day value'
            }), 400
            
        # Get exam settings
        settings = ExamSettings.query.first()
        if settings and day < settings.active_day:
            return jsonify({
                'success': False,
                'message': f'Cannot add questions for past days. Current active day is {settings.active_day}'
            }), 400
            
        # Create new question
        question = Question(
            course_id=course_id,
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer,
            day=day
        )
        
        db.session.add(question)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Question added successfully',
            'question': {
                'id': question.id,
                'course_id': course_id,
                'question_text': question_text,
                'option_a': option_a,
                'option_b': option_b,
                'option_c': option_c,
                'option_d': option_d,
                'correct_answer': correct_answer,
                'day': day
            }
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error adding question: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while adding the question'
        }), 500

@app.route('/remove_question/<int:question_id>', methods=['POST'])
@login_required
def remove_question(question_id):
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    question = Question.query.get_or_404(question_id)
    
    try:
        # First remove any related answers and selections
        Answer.query.filter_by(question_id=question.id).delete()
        QuestionSelection.query.filter_by(question_id=question.id).delete()
        
        # Then remove the question
        db.session.delete(question)
        db.session.commit()
        flash('Question removed successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error removing question: ' + str(e), 'error')
    
    # Return to the previous page (either course management or question management)
    return redirect(request.referrer or url_for('teacher_dashboard'))

@app.route('/update_active_day', methods=['POST'])
@login_required
def update_active_day():
    if not current_user.is_teacher:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
        
    try:
        new_day = request.form.get('day')
        if not new_day:
            flash('Day value is required', 'error')
            return redirect(url_for('teacher_dashboard'))
            
        new_day = int(new_day)
        if new_day < 1 or new_day > 6:
            flash('Day must be between 1 and 6', 'error')
            return redirect(url_for('teacher_dashboard'))
            
        settings = ExamSettings.query.first()
        if not settings:
            settings = ExamSettings(active_day=new_day)
            db.session.add(settings)
        else:
            settings.active_day = new_day
            
        db.session.commit()
        flash(f'Active day updated to {new_day}', 'success')
        
    except ValueError:
        flash('Invalid day value', 'error')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating the active day', 'error')
        print(f"Error updating active day: {str(e)}")
        
    return redirect(url_for('teacher_dashboard'))

@app.route('/select_question/<int:question_id>', methods=['POST'])
@login_required
def select_question(question_id):
    if current_user.is_teacher:
        flash('Teachers cannot select questions!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    question = Question.query.get_or_404(question_id)
    
    # Check if question is already selected for today
    today = date.today()
    existing_selection = QuestionSelection.query.filter_by(
        user_id=current_user.id,
        selection_date=today
    ).first()
    
    if existing_selection:
        flash('You have already selected a question for today!', 'error')
        return redirect(url_for('exam'))
    
    # Create new selection
    selection = QuestionSelection(
        user_id=current_user.id,
        question_id=question_id,
        selection_date=today
    )
    db.session.add(selection)
    db.session.commit()
    
    flash('Question selected successfully!', 'success')
    return redirect(url_for('exam'))

@app.route('/mark_absent', methods=['POST'])
@login_required
def mark_absent():
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    student_id = request.form.get('student_id')
    day = request.form.get('day')
    reason = request.form.get('reason')
    
    if not all([student_id, day, reason]):
        flash('All fields are required!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    student = User.query.get(student_id)
    if not student or student.is_teacher:
        flash('Invalid student selected!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    absence = ExamAbsence(
        user_id=student_id,
        day=day,
        reason=reason
    )
    db.session.add(absence)
    db.session.commit()
    
    flash(f'Student {student.username} has been marked absent for day {day}', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/manage_enrollments')
@app.route('/teacher/manage_enrolments')  # Add British spelling route
@login_required
def manage_enrollments():
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    students = User.query.filter_by(is_teacher=False).all()
    courses = Course.query.all()
    
    # Get enrollment data for each student
    enrollments = {}
    for student in students:
        enrollments[student.id] = [course.id for course in student.enrolled_courses]
    
    # Generate CSRF token if not present
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    return render_template('manage_enrollments.html',
                         students=students,
                         courses=courses,
                         enrollments=enrollments)

@app.route('/teacher/update_enrollment', methods=['POST'])
@login_required
def update_enrollment():
    if not current_user.is_teacher:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    student_id = request.form.get('student_id')
    course_id = request.form.get('course_id')
    action = request.form.get('action')  # 'enroll' or 'unenroll'
    
    if not all([student_id, course_id, action]):
        flash('Missing required information!', 'error')
        return redirect(url_for('manage_enrollments'))
    
    student = User.query.get(student_id)
    course = Course.query.get(course_id)
    
    if not student or not course:
        flash('Student or course not found!', 'error')
        return redirect(url_for('manage_enrollments'))
    
    if action == 'enroll':
        if course not in student.enrolled_courses:
            student.enrolled_courses.append(course)
            db.session.commit()
            flash(f'Successfully enrolled {student.username} in {course.name}', 'success')
    else:  # unenroll
        if course in student.enrolled_courses:
            student.enrolled_courses.remove(course)
            db.session.commit()
            flash(f'Successfully unenrolled {student.username} from {course.name}', 'success')
    
    return redirect(url_for('manage_enrollments'))

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def edit_question(question_id):
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    question = Question.query.get_or_404(question_id)
    settings = ExamSettings.query.first()

    if request.method == 'GET':
        return jsonify({
            'success': True,
            'question': {
                'id': question.id,
                'question_text': question.question_text,
                'option_a': question.option_a,
                'option_b': question.option_b,
                'option_c': question.option_c,
                'option_d': question.option_d,
                'correct_answer': question.correct_answer,
                'day': question.day
            }
        })

    elif request.method == 'POST':
        try:
            # Get form data
            question_text = request.form.get('question_text')
            option_a = request.form.get('option_a')
            option_b = request.form.get('option_b')
            option_c = request.form.get('option_c')
            option_d = request.form.get('option_d')
            correct_answer = request.form.get('correct_answer')
            day = request.form.get('day')

            # Validate required fields
            if not all([question_text, option_a, option_b, option_c, option_d, correct_answer, day]):
                return jsonify({
                    'success': False,
                    'message': 'All fields are required'
                }), 400

            # Validate correct answer
            if correct_answer not in ['A', 'B', 'C', 'D']:
                return jsonify({
                    'success': False,
                    'message': 'Invalid correct answer'
                }), 400

            # Validate day
            try:
                day = int(day)
                if day < 1 or day > 6:
                    return jsonify({
                        'success': False,
                        'message': 'Day must be between 1 and 6'
                    }), 400
            except ValueError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid day value'
                }), 400

            # Check if trying to edit a past day's question
            if settings and day < settings.active_day:
                return jsonify({
                    'success': False,
                    'message': f'Cannot edit questions from past days. Current active day is {settings.active_day}'
                }), 400

            # Update question
            question.question_text = question_text
            question.option_a = option_a
            question.option_b = option_b
            question.option_c = option_c
            question.option_d = option_d
            question.correct_answer = correct_answer
            question.day = day

            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Question updated successfully',
                'question': {
                    'id': question.id,
                    'question_text': question_text,
                    'option_a': option_a,
                    'option_b': option_b,
                    'option_c': option_c,
                    'option_d': option_d,
                    'correct_answer': correct_answer,
                    'day': day
                }
            })

        except Exception as e:
            db.session.rollback()
            print(f"Error updating question: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error updating question: {str(e)}'
            }), 500

    return jsonify({
        'success': False,
        'message': 'Invalid request method'
    }), 405

@app.route('/enroll_student', methods=['POST'])
@login_required
@csrf.exempt
def enroll_student():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        student_id = data.get('student_id')
        course_id = data.get('course_id')
        
        if not student_id or not course_id:
            return jsonify({'success': False, 'message': 'Student and Course are required'}), 400
            
        # Check if student exists
        student = User.query.filter_by(id=student_id, is_teacher=False).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # Check if course exists
        course = Course.query.get(course_id)
        if not course:
            return jsonify({'success': False, 'message': 'Course not found'}), 404
            
        # Check if already enrolled
        if course in student.enrolled_courses:
            return jsonify({'success': False, 'message': 'Student already enrolled in this course'}), 400
            
        # Enroll student
        student.enrolled_courses.append(course)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully enrolled {student.username} in {course.name}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error enrolling student: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while enrolling student'}), 500

@app.route('/unenroll_student', methods=['POST'])
@login_required
@csrf.exempt
def unenroll_student():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        student_id = data.get('student_id')
        course_id = data.get('course_id')
        
        if not student_id or not course_id:
            return jsonify({'success': False, 'message': 'Student and Course are required'}), 400
            
        # Check if student exists
        student = User.query.filter_by(id=student_id, is_teacher=False).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # Check if course exists
        course = Course.query.get(course_id)
        if not course:
            return jsonify({'success': False, 'message': 'Course not found'}), 404
            
        # Check if enrolled
        if course not in student.enrolled_courses:
            return jsonify({'success': False, 'message': 'Student not enrolled in this course'}), 400
            
        # Unenroll student
        student.enrolled_courses.remove(course)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully unenrolled {student.username} from {course.name}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error unenrolling student: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while unenrolling student'}), 500

@app.route('/get_students', methods=['GET'])
@login_required
@csrf.exempt
def get_students():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        students = User.query.filter_by(is_teacher=False).all()
        return jsonify({
            'success': True,
            'students': [{
                'id': student.id,
                'username': student.username,
                'courses': [{
                    'id': course.id,
                    'name': course.name
                } for course in student.courses]
            } for student in students]
        })
        
    except Exception as e:
        print(f"Error getting students: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while getting students'}), 500

@app.route('/get_timer_status')
@login_required
def get_timer_status():
    if current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Teachers cannot take exams'}), 403
    
    try:
        enrolled_courses = current_user.enrolled_courses
        timer_data = {}
        current_time = datetime.utcnow()
        
        for course in enrolled_courses:
            if course.timer:
                duration_minutes = int(course.timer.duration_minutes)
                timer_data[str(course.id)] = {
                    'name': course.name,
                    'duration_minutes': duration_minutes,
                    'start_time': course.timer.start_time.isoformat() if course.timer.start_time else None,
                    'end_time': course.timer.end_time.isoformat() if course.timer.end_time else None,
                    'active': course.timer_active
                }
                
                # If timer is active but not started, initialize it
                if course.timer_active and not course.timer.start_time:
                    course.timer.start_time = current_time
                    course.timer.end_time = current_time + timedelta(minutes=duration_minutes)
                    db.session.commit()
                    
                    # Update the response with new times
                    timer_data[str(course.id)].update({
                        'start_time': course.timer.start_time.isoformat(),
                        'end_time': course.timer.end_time.isoformat()
                    })
        
        return jsonify({
            'success': True,
            'timers': timer_data,
            'server_time': current_time.isoformat()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_timer', methods=['POST'])
@login_required
def update_timer():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Only teachers can update timers'}), 403
    
    try:
        course_id = request.form.get('course_id')
        duration = int(request.form.get('duration', 60))
        timer_active = request.form.get('timer_active') == 'on'
        
        course = Course.query.get_or_404(course_id)
        
        if not course.timer:
            course.timer = ExamTimer(duration_minutes=duration)
            db.session.add(course.timer)
        else:
            course.timer.duration_minutes = duration
        
        # Reset timer state if activating
        if timer_active and not course.timer_active:
            current_time = datetime.utcnow()
            course.timer.start_time = current_time
            course.timer.end_time = current_time + timedelta(minutes=duration)
        elif not timer_active:
            course.timer.start_time = None
            course.timer.end_time = None
        
        course.timer_active = timer_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Timer updated successfully',
            'timer': {
                'duration_minutes': duration,
                'active': timer_active,
                'start_time': course.timer.start_time.isoformat() if course.timer.start_time else None,
                'end_time': course.timer.end_time.isoformat() if course.timer.end_time else None
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/reset_timer', methods=['POST'])
@login_required
def reset_timer():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Only teachers can reset timers'}), 403
    
    try:
        course_id = request.form.get('course_id')
        course = Course.query.get_or_404(course_id)
        
        if course.timer:
            # Reset only timer state
            course.timer.start_time = None
            course.timer.end_time = None
            course.timer_active = False
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Timer reset successfully',
                'timer': {
                    'duration_minutes': course.timer.duration_minutes,
                    'active': False,
                    'start_time': None,
                    'end_time': None,
                    'course_id': course_id
                }
            })
        else:
            return jsonify({'success': False, 'message': 'No timer found for this course'}), 404
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/reset_all_timers', methods=['POST'])
@login_required
def reset_all_timers():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        # Get all courses with timers
        courses_with_timers = Course.query.filter(Course.timer != None).all()
        course_ids = [course.id for course in courses_with_timers]
        
        # Reset timer states
        ExamTimer.query.update({
            'start_time': None,
            'end_time': None
        })
        Course.query.update({'timer_active': False})
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'All timers reset successfully',
            'reset_courses': course_ids
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_all_timers', methods=['POST'])
@login_required
def update_all_timers():
    if not current_user.is_teacher:
        return redirect(url_for('teacher_dashboard'))
    
    try:
        duration = request.form.get('duration', type=int)
        all_timers_active = request.form.get('all_timers_active') == 'on'
        current_time = datetime.utcnow()
        
        courses = Course.query.all()
        for course in courses:
            if not course.timer:
                timer = ExamTimer(
                    course_id=course.id,
                    duration_minutes=duration
                )
                db.session.add(timer)
                course.timer = timer
            else:
                course.timer.duration_minutes = duration
            
            course.timer_active = all_timers_active
            if all_timers_active and not course.timer.start_time:
                course.timer.start_time = current_time
                course.timer.end_time = current_time + timedelta(minutes=duration)
        
        db.session.commit()
        flash('All timer settings updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating timers: {str(e)}', 'error')
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/edit_answer', methods=['POST'])
@login_required
def edit_answer():
    if current_user.is_teacher:
        flash('Teachers cannot edit answers!', 'error')
        return redirect(url_for('index'))

    question_id = request.form.get('question_id')
    new_answer = request.form.get('answer')

    if not question_id or not new_answer:
        flash('Invalid submission. Please try again.', 'error')
        return redirect(url_for('exam'))

    # Get the existing answer
    answer = Answer.query.filter_by(
        user_id=current_user.id,
        question_id=question_id,
        selection_date=date.today()
    ).first()

    if not answer:
        flash('No answer found to edit!', 'error')
        return redirect(url_for('exam'))

    # Get the question to verify it exists and belongs to an active course
    question = Question.query.get(question_id)
    if not question:
        flash('Question not found!', 'error')
        return redirect(url_for('exam'))

    # Check if the course timer is active and not expired
    course = question.course
    if not course or not course.timer_active:
        flash('This exam is not currently active!', 'error')
        return redirect(url_for('exam'))

    if check_timer_expired(course):
        flash('The exam timer has expired!', 'error')
        return redirect(url_for('exam'))

    try:
        # Update the answer
        answer.selected_answer = new_answer
        db.session.commit()
        flash('Answer updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating answer. Please try again.', 'error')
        print(f"Error updating answer: {str(e)}")

    return redirect(url_for('exam'))

@app.route('/export_answers', methods=['POST'])
@login_required
def export_answers():
    if not current_user.is_teacher:
        flash('Only teachers can export answers', 'error')
        return redirect(url_for('index'))
    
    try:
        course_id = request.form.get('course_id')
        day = request.form.get('day', type=int)
        
        if not course_id or not day:
            flash('Course ID and day are required', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Get the course
        course = Course.query.get_or_404(course_id)
        
        # Get all answers for this course's questions on the specified day
        answers = db.session.query(
            User.username,
            Question.question_text,
            Question.option_a,
            Question.option_b,
            Question.option_c,
            Question.option_d,
            Question.correct_answer,
            Answer.selected_answer,
            Answer.selection_date
        ).join(
            Answer, Answer.user_id == User.id
        ).join(
            Question, Question.id == Answer.question_id
        ).filter(
            Question.course_id == course_id,
            Answer.day == day,
            User.is_teacher == False
        ).order_by(
            User.username,
            Question.id
        ).all()
        
        if not answers:
            flash(f'No answers found for day {day}', 'warning')
            return redirect(url_for('teacher_dashboard'))
        
        # Create DataFrame
        df = pd.DataFrame(answers, columns=[
            'Student',
            'Question',
            'Option A',
            'Option B',
            'Option C',
            'Option D',
            'Correct Answer',
            'Selected Answer',
            'Submission Date'
        ])
        
        # Add a column to show if the answer was correct
        df['Is Correct'] = df['Correct Answer'] == df['Selected Answer']
        
        # Calculate score for each student
        student_scores = df.groupby('Student').agg({
            'Question': 'count',
            'Is Correct': 'sum'
        }).reset_index()
        student_scores.columns = ['Student', 'Total Questions', 'Correct Answers']
        student_scores['Score (%)'] = (student_scores['Correct Answers'] / student_scores['Total Questions'] * 100).round(2)
        
        # Create CSV output
        output = io.StringIO()
        
        # Write the header
        output.write("Export Date: {}\n".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        output.write("Course: {}\n".format(course.name))
        output.write("Day: {}\n\n".format(day))
        
        # Write the summary section
        output.write("SUMMARY\n")
        student_scores.to_csv(output, index=False)
        output.write("\n\nDETAILED ANSWERS\n")
        df.to_csv(output, index=False)
        
        # Create the response
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={course.name}_Day{day}_Answers.csv"
        response.headers["Content-type"] = "text/csv"
        
        return response
        
    except Exception as e:
        flash(f'Error exporting answers: {str(e)}', 'error')
        return redirect(url_for('teacher_dashboard'))

@app.route('/clear_answers', methods=['POST'])
@login_required
def clear_answers():
    if not current_user.is_teacher:
        flash('Only teachers can clear answers', 'error')
        return redirect(url_for('index'))
    
    try:
        course_id = request.form.get('course_id')
        day = request.form.get('day', type=int)
        
        if not course_id or not day:
            flash('Course ID and day are required', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Get the course
        course = Course.query.get_or_404(course_id)
        
        # First get the question IDs for this course
        question_ids = [q.id for q in Question.query.filter_by(course_id=course_id).all()]
        
        if not question_ids:
            flash(f'No questions found for {course.name}', 'warning')
            return redirect(url_for('teacher_dashboard'))
        
        # Then delete answers for these questions on the specified day
        deleted = Answer.query.filter(
            Answer.question_id.in_(question_ids),
            Answer.day == day
        ).delete(synchronize_session=False)
        
        db.session.commit()
        
        if deleted > 0:
            flash(f'Successfully cleared {deleted} answers for {course.name} Day {day}', 'success')
        else:
            flash(f'No answers found to clear for {course.name} Day {day}', 'info')
            
        return redirect(url_for('teacher_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing answers: {str(e)}', 'error')
        return redirect(url_for('teacher_dashboard'))

@app.route('/delete_student', methods=['POST'])
@login_required
def delete_student():
    if not current_user.is_teacher:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        student_id = request.json.get('student_id')
        if not student_id:
            return jsonify({'success': False, 'message': 'Student ID is required'}), 400
            
        student = User.query.filter_by(id=student_id, is_teacher=False).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # Delete related records first
        Answer.query.filter_by(user_id=student_id).delete()
        QuestionSelection.query.filter_by(user_id=student_id).delete()
        ExamSubmission.query.filter_by(user_id=student_id).delete()
        ExamAbsence.query.filter_by(user_id=student_id).delete()
        StudentCourse.query.filter_by(student_id=student_id).delete()
        
        # Delete the student
        db.session.delete(student)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Student {student.username} has been deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

def check_timer_expired(course):
    """Check if the exam timer has expired for a course."""
    if not course.timer or not course.timer_active:
        return False
    
    if not course.timer.end_time:
        return False
    
    return datetime.utcnow() > course.timer.end_time

def get_answer(user_id, question_id):
    """Get the user's answer for a specific question on the current day."""
    settings = ExamSettings.query.first()
    if not settings:
        return None
    return Answer.query.filter_by(
        user_id=user_id,
        question_id=question_id,
        day=settings.active_day
    ).first()

if __name__ == '__main__':
    with app.app_context():
        # Create instance directory if it doesn't exist
        instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
        os.makedirs(instance_path, exist_ok=True)
        
        # Create all tables
        db.create_all()
        
        # Add timer_active column if it doesn't exist
        inspector = inspect(db.engine)
        if 'timer_active' not in [col['name'] for col in inspector.get_columns('course')]:
            db.session.execute('ALTER TABLE course ADD COLUMN timer_active BOOLEAN DEFAULT FALSE')
            db.session.commit()
            print("Added timer_active column to course table")
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', is_teacher=True)
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user")
            
        # Create default exam settings if they don't exist
        settings = ExamSettings.query.first()
        if not settings:
            settings = ExamSettings()
            db.session.add(settings)
            db.session.commit()
            print("Created default exam settings")
            
    app.run(debug=True, port=5001)
