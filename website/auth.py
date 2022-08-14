from flask import Blueprint, render_template, request, redirect, url_for, session
import flask
from flask.helpers import flash
from .models import *
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        type = user.type
        if user:
            if user.password == password:
                flash('Logged in succesfully')
                login_user(user)
                session["email"] = email
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect email or password')
                return redirect(url_for('auth.login'))
        else:
            flash('User doesnot exists')
            return redirect(url_for('auth.signup'))

    return render_template('login.html')


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        address = request.form.get('address')
        telephone = request.form.get('telephone')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already exists')
            return redirect(url_for('auth.login'))
        else:
            new_user = User(email=email, name=name, password=password, address=address, telephone=telephone)
            db.session.add(new_user)
            db.session.commit()
            flash('User Created!')

            user = User.query.filter_by(email=email).first()
            login_user(user)

            return redirect(url_for('views.home'))

    return render_template('signup.html')