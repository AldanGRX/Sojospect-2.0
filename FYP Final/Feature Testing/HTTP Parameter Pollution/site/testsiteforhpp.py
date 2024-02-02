from flask import Flask, jsonify, request, render_template
import re
from urllib.parse import unquote
import mysql.connector

app = Flask(__name__)

order = 'first'
DB_HOST="127.0.0.1"
DB_USER="root"
DB_PASSWORD="password"

db = mysql.connector.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD
)

# Create a cursor object
cursor = db.cursor()

cursor.execute("SHOW DATABASES")
databases = [database[0] for database in cursor]

if 'hpp_test_db' not in databases:
    cursor.execute("CREATE DATABASE hpp_test_db")
    cursor.execute("USE hpp_test_db;")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id int NOT NULL AUTO_INCREMENT,
        username varchar(255) NOT NULL,
        PRIMARY KEY (id)
    )
    """)

    cursor.execute('INSERT INTO users(username) VALUES("Bob");')
    cursor.execute('INSERT INTO users(username) VALUES("John");')
    cursor.execute('INSERT INTO users(username) VALUES("Sam");')
    cursor.execute('INSERT INTO users(username) VALUES("Tim");')
    db.commit()
cursor.close()
db.close()

# HTML form for the POST request
# HTML form for the PUT request
@app.route('/', methods=['GET'])
def form_index():
    return render_template('form_get.html')

@app.route('/form_get', methods=['GET'])
def form_index2():
    return render_template('form_get.html')

@app.route('/hpp_xss_bad', methods=['GET'])
def hpp_xss_bad():
    args_dict = request.args.to_dict(flat=False)
    '''
    username param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    
    if "username" in args_dict.keys():
        #Obtain first value
        front_end_username = args_dict['username'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_username)):
            return "Bad Chars Found"
        
        #Validation passed, proceed to pass arguments to backend
        #Backend uses last parameter
        backend_username = args_dict['username'][-1 if order=='first' else 0] 
        return render_template('disp_username_bad.html',username=backend_username)
    else:
        return '<h1>username argument not found</h1>'

@app.route('/hpp_xss_bad_2', methods=['GET'])
def hpp_xss_bad_2():
    args_dict = request.args.to_dict(flat=False)
    '''
    link param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    
    if "link" in args_dict.keys():
        #Obtain first value
        front_end_link = args_dict['link'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_link)):
            return "Bad Chars Found"
        
        #Validation passed, proceed to pass arguments to backend
        #Backend uses last parameter
        backend_link = args_dict['link'][-1 if order=='first' else 0] 
        return render_template('disp_link_bad.html',link=backend_link)
    else:
        return '<h1>link argument not found</h1>'

@app.route('/hpp_encoding_bad', methods=['GET'])
def hpp_encoding_bad():
    args_dict = request.args.to_dict(flat=False)
    '''
    link param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    print(request.url)
    if "link" in args_dict.keys():
        #Obtain first value
        front_end_link = args_dict['link'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_link)):
            return "Bad Chars Found"
        
        #Validation passed
        return render_template('disp_link_bad.html',link=unquote(request.url))
    else:
        return '<h1>link argument not found</h1>'
@app.route('/hpp_encoding_safe', methods=['GET'])
def hpp_encoding_safe():
    args_dict = request.args.to_dict(flat=False)
    '''
    link param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    print(request.url)
    if "link" in args_dict.keys():
        #Obtain first value
        front_end_link = args_dict['link'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_link)):
            return "Bad Chars Found"
        
        #Validation passed
        return render_template('disp_link_safe.html',link=request.url)
    else:
        return '<h1>link argument not found</h1>'

@app.route('/hpp_xss_safe', methods=['GET'])
def hpp_xss_safe():
    args_dict = request.args.to_dict(flat=False)
    '''
    username param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    
    if "username" in args_dict.keys():
        #Obtain first value
        front_end_username = args_dict['username'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_username)):
            return "Bad Chars Found"
        
        #Validation passed, proceed to pass arguments to backend
        #Backend uses last parameter
        backend_username = args_dict['username'][-1 if order=='first' else 0] 
        return render_template('disp_username_safe.html',username=backend_username)
    else:
        return '<h1>username argument not found</h1>'

@app.route('/hpp_xss_safe_2', methods=['GET'])
def hpp_xss_safe_2():
    args_dict = request.args.to_dict(flat=False)
    '''
    link param -> Display to site
        - Front-End perform input validation
    abc param -> Does nothing, to check the capability of the script
    '''

    #Simulating Front End Server
    #Front End Server reads the first parameter, validates and pass on request to Back End Server
    
    if "link" in args_dict.keys():
        #Obtain first value
        front_end_link = args_dict['link'][0 if order=='first' else -1]
        #Validation
        if bool(re.search('[^a-zA-Z0-9]+',front_end_link)):
            return "Bad Chars Found"
        
        #Validation passed, proceed to pass arguments to backend
        #Backend uses last parameter
        backend_link = args_dict['link'][-1 if order=='first' else 0] 
        return render_template('disp_link_safe.html',link=backend_link)
    else:
        return '<h1>link argument not found</h1>'
    
@app.route('/hpp_sql_safe', methods=['GET'])
def hpp_sql_safe():
    args_dict = request.args.to_dict(flat=False)
    if "username" in args_dict.keys():
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database="hpp_test_db"
        )

        # Create a cursor object
        cursor = db.cursor()
        query = "SELECT * from users where username=%s"
        cursor.execute(query,[args_dict['username'][0]])
        data = cursor.fetchone()
        cursor.close()
        db.close()
        if data is not None:
            id = data[0]
            username = data[1]
            return render_template("disp_sql.html",id=id,username=username)
        else:
            return '<h1>Username not found</h1>'
    return '<h1>username argument not found</h1>'

#To test for Blind
@app.route('/hpp_sql_safe_2', methods=['GET'])
def hpp_sql_safe_2():
    args_dict = request.args.to_dict(flat=False)
    if "username" in args_dict.keys():
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database="hpp_test_db"
        )

        # Create a cursor object
        cursor = db.cursor()
        query = "SELECT * from users where username=%s"
        try:
            cursor.execute(query,[args_dict['username'][0]])
            data = cursor.fetchone()
            cursor.close()
            db.close()
            if data is not None:
                id = data[0]
                username = data[1]
                return render_template("disp_sql.html",id=id,username=username)
            else:
                return 'Blank'
        except Exception as e:
            return 'Blank'
    return '<h1>username argument not found</h1>'

        
@app.route('/hpp_sql_bad', methods=['GET'])
def hpp_sql_bad():
    args_dict = request.args.to_dict(flat=False)
    if "username" in args_dict.keys():
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database="hpp_test_db"
        )

        # Create a cursor object
        cursor = db.cursor()
        query = "SELECT * from users where username=" +"'" +args_dict['username'][0]+"';"
        try:
            cursor.execute(query,[])
            data = cursor.fetchone()
            cursor.close()
            db.close()
            if data is not None:
                id = data[0]
                username = data[1]
                return render_template("disp_sql.html",id=id,username=username)
            else:
                return '<h1>Username not found</h1>'
        except Exception as e:
            print(e)
            return str(e)
    return '<h1>username argument not found</h1>'

#To test for blind SQL
@app.route('/hpp_sql_bad_2', methods=['GET'])
def hpp_sql_bad_2():
    args_dict = request.args.to_dict(flat=False)
    if "username" in args_dict.keys():
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database="hpp_test_db"
        )

        # Create a cursor object
        cursor = db.cursor()
        query = "SELECT * from users where username=" +"'" +args_dict['username'][0]+"';"
        try:
            cursor.execute(query,[])
            data = cursor.fetchone()
            cursor.close()
            db.close()
            if data is not None:
                id = data[0]
                username = data[1]
                return render_template("disp_sql.html",id=id,username=username)
            else:
                return 'Blank'
        except Exception as e:
            return 'Blank'
    return '<h1>username argument not found</h1>'


@app.route('/hpp_xss_nothing', methods=['GET'])
def hpp_xss_nothing():
    return 'This site does nothing'

@app.route('/form_post', methods=['GET'])
def form_for_sql_blind_i() :
    return render_template('form_post.html')

@app.route('/register', methods=['POST'])
def register() :
    data = request.form
    username = data.get('username')
    password = data.get('password')

    db = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database="hpp_test_db"
    )
    # Create a cursor object
    cursor = db.cursor()
    try:
        # check if user exists
        query = f"SELECT * FROM users WHERE username='{username}';"
        cursor.execute(query)
        existing_user = cursor.fetchone()
        print(existing_user)
        # print(existing_user)

        if existing_user == None : # check if user don't exist, if dont exist, insert into database
            query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}');"
            cursor.execute(query)
            db.commit()
            cursor.close()
            db.close()
            return render_template('form_post.html', username=f'{username} is created successfully')
        else :
            # print('Helo')
            return render_template('form_post.html', username=f'{username} exists')
       
    except Exception as e:
        print(e)
        if e.errno == '1062' :
            return render_template('form_post.html', username=f'{username} exists')
        else :
            return render_template('form_post.html', username=f'error')


if __name__ == '__main__':
    # Run the application on http://127.0.0.1:5000/
    app.run(debug=True)