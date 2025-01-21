#!/usr/bin/env python3
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('inventory_items', lazy=True))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'))
    item_name = db.Column(db.String(150), nullable=False)
    source = db.Column(db.Integer)  # Source (old quantity)
    target = db.Column(db.Integer)  # Target (new quantity)
    delta = db.Column(db.Integer)   # Delta (change in quantity)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    item = db.relationship('InventoryItem', backref=db.backref('logs', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        description = request.form['description']
        item = InventoryItem(name=name, quantity=quantity, description=description, user_id=current_user.id)
        db.session.add(item)
        db.session.commit()

        # Log the "Added" action
        log = Log(action="Added", item_name=name, user_id=current_user.id, item_id=item.id)
        db.session.add(log)
        db.session.commit()

        flash('Item added to inventory.', 'success')

    items = InventoryItem.query.filter_by(user_id=current_user.id).all()
    return render_template('inventory.html', items=items)


@app.route('/delete/<int:item_id>')
@login_required
def delete_item(item_id):
    item = InventoryItem.query.get(item_id)
    if item and item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()

        # Log the "Deleted" action
        log = Log(action="Deleted", item_name=item.name, user_id=current_user.id, item_id=item.id)
        db.session.add(log)
        db.session.commit()

        flash('Item deleted from inventory.', 'success')
    return redirect(url_for('inventory'))


@app.route('/edit_quantity', methods=['POST'])
@login_required
def edit_quantity():
    item_id = request.form['item_id']
    new_quantity = int(request.form['quantity'])  # Ensure quantity is an integer
    item = InventoryItem.query.get(item_id)

    if item and item.user_id == current_user.id:
        old_quantity = item.quantity  # Get the old quantity
        delta = new_quantity - old_quantity  # Calculate the change in quantity
        
        # Update the item's quantity
        item.quantity = new_quantity
        db.session.commit()

        # Log the action with source, target, and delta
        log = Log(
            action="Edited Quantity",
            item_name=item.name,
            user_id=current_user.id,
            item_id=item.id,
            source=old_quantity,
            target=new_quantity,
            delta=delta
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'message': f'Quantity updated successfully! Old Quantity: {old_quantity}, New Quantity: {new_quantity}, Delta: {delta}'})
    
    return jsonify({'message': 'Item not found or unauthorized.'})


@app.route('/log')
@login_required
def log_page():
    logs = Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc()).all()
    return render_template('log.html', logs=logs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
