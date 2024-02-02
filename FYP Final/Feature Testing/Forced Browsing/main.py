from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/secret1')
def secret1():
    return render_template('secret1.html')

@app.route('/secret2')
def secret2():
    return render_template('secret2.html')

@app.route('/secret')
def secret():
    return render_template('secret.html')

if __name__ == "__main__":
    app.run('localhost',port=5051)