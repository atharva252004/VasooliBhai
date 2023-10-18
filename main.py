from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import pbkdf2_sha256 as sha256
from user_payments import get_column_as_list, good_bad

app = Flask(__name__)
cors = CORS(app)
app.secret_key = 'your_secret_key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_database.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template("index.html")
    # return 'Welcome to the User Management App'

@app.route('/payment_history', methods=['GET', 'POST'])
def display_emi_history():

    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()

        due_dates = get_column_as_list(user.username, 'due_date')
        payment_dates = get_column_as_list(user.username, 'payment_date')
        agreement_numbers = get_column_as_list(user.username, 'agreement_number')

        payment_data = []

        # Create a list of dictionaries
        for due_date, payment_date in zip(due_dates, payment_dates):
            date_dict = {"due_date": due_date, "payment_date": payment_date}
            payment_data.append(date_dict)

        return jsonify({payment_data})
    else:
        return jsonify({'error': 'user_not_registered'})



@app.route('/register', methods=['GET', 'POST'])
@cross_origin()
def register():
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # Use SHA-256 for hashing
        # hashed_password = sha256.hash(password)
        # hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        response = jsonify({'status': 'successful'})
        response.headers.add("Access-Control-Allow-Origin", "*")
        flash('User registered successfully!', 'success')
        return response

    return jsonify({'status': 'unsuccessful'})

@app.route('/login', methods=['GET', 'POST'])
@cross_origin()
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return jsonify({'status': 'successful'})
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return jsonify({'status': 'unsuccessful'})

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()

        if good_bad(user.username):
            return render_template('good_user.html');
        else:
            return render_template('bad_user.html');

        return f'Welcome, {user.first_name} {user.last_name}! This is your dashboard.'
    else:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return jsonify({'status': 'successful'})

if __name__ == '__main__':
    app.run(debug=True)

