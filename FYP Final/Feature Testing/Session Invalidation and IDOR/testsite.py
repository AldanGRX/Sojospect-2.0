from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'asdioj012e0ihxq0n21ewn'

# Dummy user data (replace with your actual user database)
users = {
    '1': {'username': 'john', 'email': 'john@example.com', 'location': 'New York'},
    '2': {'username': 'jane', 'email': 'jane@example.com', 'location': 'Los Angeles'}
}

products = {
    '1': {'user_id' : '1', 'name' : 'John\'s product', 'price': 10},
    '2': {'user_id' : '2', 'name' : 'Jane\'s product', 'price': 20}
}

# Dummy authentication function (replace with your actual authentication logic)
def authenticate(username, password):
    for user_id, user_info in users.items():
        if user_info['username'] == username and password == "password":
            return True
    return False

@app.route('/', methods=['GET'])
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/profile/<user_id>')
def profile(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_info = users.get(user_id)
    if not user_info:
        return 'User not found', 404
    return render_template('profile.html', user_info=user_info)

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    # Get the user_id based on the username
    user_id = None
    for uid, user_info in users.items():
        if user_info['username'] == username:
            user_id = uid
            break
    if user_id is None:
        return 'User ID not found for the logged-in user', 404
    return render_template('home.html', username=username, user_id=user_id)

@app.route('/product/<user_id>/<product_id>')
def view_product(user_id, product_id):
    # You can add logic here to ensure that the user has access to view this product
    product_info = products.get(product_id)
    if not product_info:
        return 'Product not found', 404
    return render_template('product.html', product_info=product_info)


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=8000)


