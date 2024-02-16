from flask import Flask, flash, render_template, request, send_file, send_from_directory,  make_response, redirect, jsonify, session, abort, url_for, g
import signal
import mysql.connector
import configparser
import webbrowser
import os
import subprocess
import functools
from datetime import datetime
import yaml
from fpdf import FPDF, TitleStyle
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace
from v2.yaml_vuln import vuln_extract #File
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlsplit
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define a list of routes that do not require authentication
AUTH_EXEMPT_ROUTES = ['/login', '/']

# Load the configuration file
config = configparser.ConfigParser()
config.read('config.ini')

# Get values from the config file
db_host = config.get('SQL Database', 'db_host')
db_user = config.get('SQL Database', 'db_user')
db_password = config.get('SQL Database', 'db_password')

# Configure MySQL connection
db = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password
)

# Create a cursor object
cursor = db.cursor()

# Check if the 'vulnerabilities' database exists
cursor.execute("SHOW DATABASES")
databases = [database[0] for database in cursor]

if 'vulnerabilities' not in databases:
    # Create the 'vulnerabilities' database
    cursor.execute("CREATE DATABASE vulnerabilities")

# Switch to the 'vulnerabilities' database
db = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database="vulnerabilities"
)
cursor = db.cursor()

# Create the 'users' table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin TINYINT(1),
    username VARCHAR(50),
    password VARCHAR(255)
)
""")

# Create the 'scans' table
cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userid INT,
    date_of_scan DATETIME,
    report_name VARCHAR(255),
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
)
""")

# Create the 'vulnerabilities' table
cursor.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    vulnerability_name VARCHAR(255),
    vulnerability_id VARCHAR(255),
    url VARCHAR(3000),
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    additional_information LONGTEXT
)
""")




# Check if 'users' table is empty
cursor.execute("SELECT COUNT(*) FROM users")
user_count = cursor.fetchone()[0]

# If no users exist, prompt to create an admin account
if user_count == 0:
    admin_username = input("Enter admin username: ")
    admin_password = generate_password_hash(input("Enter admin password: "))

    # Insert the admin account into the 'users' table
    cursor.execute("INSERT INTO users (admin, username, password) VALUES (1, %s, %s)", (admin_username, admin_password))
    db.commit()


option_to_name_mapping = {"scan_for_forced_browsing":"Forced Browsing",
"scan_for_insecure_direct_object_references":"Insecure Direct Object References",
"scan_for_weak_ssl":"Weak SSL Configurations",
"scan_for_sql":"SQL Injection",
"scan_for_xss":"Cross-site Scripting",
"scan_for_unrestricted_file_upload":"Unrestricted File Upload",
"scan_for_http_parameter_pollution":"HTTP Parameter Pollution",
"scan_for_robots_txt":"Robots.txt Check",
"scan_for_overinformative_error":"Overinformative Error",
"scan_for_cookie_attribute_checking":"Weak Cookie Configurations",
"scan_for_allowed_http_methods":"Allowed HTTP Methods",
"scan_for_csrf":"Cross Site Request Forgery",
"scan_for_clickjacking":"Clickjacking",
"scan_for_session_hijacking":"Session Hijacking",
"scan_for_bruteforce":"Bruteforce",
"scan_for_session_fixation":"Session Fixation",
"scan_for_session_invalidation":"Session Invalidation",
"scan_for_ssrf":"Server-Side Request Forgery",
"scan_for_vuln_outdated_components":"Vulnerable and Outdated Components",}

global_conducted_scans = []

@app.route('/')
def login_page():
    return render_template('login.html')

def check_credentials(username, password):
    cursor = db.cursor(buffered=True)
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, [username])
    user = cursor.fetchone()
    cursor.close()
    if len(user) == 0:
        return None
    if check_password_hash(user[3],password):
        return user
    else:
        return None
        
# Define a route for the login request
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        # Handle JSON request
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Perform authentication logic
        user = check_credentials(username, password)
        if user:
            session['username'] = username  # Store the authenticated username in the session
            session['admin'] = user[1]  # Store the admin value in the session
            session['userid'] = user[0]
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    else:
        # Handle HTML request (form submission)
        username = request.form['username']
        password = request.form['password']

        # Perform authentication logic
        user = check_credentials(username, password)
        if user:
            session['username'] = username  # Store the authenticated username in the session
            session['admin'] = user[1]  # Store the admin value in the session
            session['userid'] = user[0]
            return redirect('/') 
        else:
            return redirect('/login')  # Redirect back to the login page with an error message

def admin_required(route_func):
    @functools.wraps(route_func)
    def decorated_route(*args, **kwargs):
        if session.get('admin'):
            return route_func(*args, **kwargs)
        else:
            abort(401)  # Unauthorized

    return decorated_route

def is_authenticated():
    return 'username' in session

@app.before_request
def before_request():
    if request.path not in AUTH_EXEMPT_ROUTES and not is_authenticated():
        print("Not logged in")
        abort(401)
    else:
        print(session)

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the session data
    session.clear()

    # Redirect the user to the login page
    return redirect(url_for('login_page'))

# Set up a route to fetch data from the MySQL table
@app.route('/website4', methods=['GET', 'POST'])
def vulnerabilities():
    connection = mysql.connector.connect( #Added this
    host=db_host,
    user=db_user,
    password=db_password,
    database='vulnerabilities'
    )
    cursor = connection.cursor()
    #Get vulnerabilities related to the user id
    query = "SELECT id,date_of_scan from scans where userid=%s ORDER BY id DESC" #session['userid']
    cursor.execute(query,[session['userid']])
    scans_data = cursor.fetchall()
    query = "SELECT vulnerability_id,url from vulnerabilities where scan_id=%s"
    # is there a better way to do the following?

    all_data = []
    for i in scans_data:
        cursor.execute(query,[i[0]])
        data = cursor.fetchall()
        
        for row in data:
            row = list(row)
            row.append(i[1])
            row.append(i[0])
            all_data.append(row)
        if (len(data) == 0):
            all_data.append(["NONE","NONE",i[1],i[0]])
    for row in all_data:
        cwe_id = row[0]
        if(cwe_id != "NONE"):
            vuln_yml = vuln_extract(cwe_id)
            row[0] = vuln_yml['name']
            row.insert(0,vuln_yml['severity'])
        else:
            row.insert(0,"NONE")
    if (request.method == "POST"):
        startDate = request.form['startDate']
        endDate = request.form['endDate']
        for row in all_data[:]:
            date = str(row[3].date())
            if startDate != '' and endDate != '' and not startDate <= date <= endDate:
                all_data.remove(row)
            elif startDate != '' and not startDate <= date:
                all_data.remove(row)
            elif endDate != '' and not date <= endDate:
                all_data.remove(row)
    print(all_data)
    cursor.close()
    connection.close()
    username = session['username']
    admin = session['admin']
    return render_template('Website4.html', data=all_data, username=username, admin=admin)

@app.route('/website')
def website1():
    # Connect to the MySQL database
    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database='vulnerabilities'
    )
    cursor = db_connection.cursor()
    # Fetch latest scan
    cursor.execute("SELECT id FROM scans where userid=%s ORDER BY id DESC LIMIT 1",[session['userid']])
    latest_scan = cursor.fetchone() # Either none or tuple
    if latest_scan is None:
        # Handle case where no data is found
        latest_url = None
        lowrisk = 0
        mediumrisk = 0
        highrisk = 0
        conductedscans = 0
    else:
        # print(latest_scan[0])
        latest_scan = latest_scan[0]
        cursor.execute("SELECT COUNT(id) FROM vulnerabilities where scan_id=%s",[latest_scan])
        latest_count_vulnerabilities = cursor.fetchone()
        #Assuming no vulnerabilities
        # print(latest_count_vulnerabilities)
        #Grab number of scans conducted
        cursor.execute("SELECT COUNT(id) FROM scans where userid=%s",[session['userid']])
        conductedscans = cursor.fetchone()[0]
        if latest_count_vulnerabilities[0] == 0:
            
            latest_url = None
            lowrisk = 0
            mediumrisk = 0
            highrisk = 0
        else:
            cursor.execute("SELECT id,url FROM vulnerabilities WHERE scan_id = %s ORDER BY id DESC LIMIT 1", (latest_scan,))
            latest_url = cursor.fetchone()[1]
            # Count the total number of high and low risk
            highrisk = 0
            mediumrisk = 0
            lowrisk = 0
            cursor.execute("SELECT vulnerability_id FROM vulnerabilities WHERE scan_id = %s", (latest_scan,))
            for vuln_id in cursor.fetchall():
                vuln_yml = vuln_extract(vuln_id[0])
                if(vuln_yml['severity'] == 'Low'):
                    lowrisk+=1
                elif(vuln_yml['severity'] == 'Medium'):
                    mediumrisk+=1
                elif(vuln_yml['severity'] == 'High'):
                    highrisk+=1
    
    cursor.close()
    db_connection.close()

    username = session['username']
    admin = session['admin']

    return render_template('Website.html', lowrisk=lowrisk, mediumrisk=mediumrisk, highrisk=highrisk,
                            conductedscans=conductedscans, currenttargets=latest_url,
                            currentvulnerabilities=highrisk+mediumrisk+lowrisk, username=username, admin=admin)

def toc_render(pdf, outline):
    
    pdf.set_font("Arial", "B", size=24)
    pdf.underline = True
    pdf.cell(text="Table of Contents", new_x="LMARGIN",new_y="NEXT")
    pdf.underline = False
    pdf.set_font("Courier", size=12)
    pdf.y+=8
    for section in outline:
        link = pdf.add_link()
        pdf.set_link(link,page=section.page_number)
        pdf.set_margin(10)
        pdf.y+=2
        # pdf.set_char_spacing(1)
        pdf.cell(text=f'{" " * section.level * 2} {section.name} {"." * (60 - section.level*2 - len(section.name))} {section.page_number}', align="C", link=link, new_x="LMARGIN",new_y="NEXT")

def pdf_generator(username, date, target, conducted_scans, vulnerabilities, high_severity, medium_severity, low_severity):
    border_trigger = 0
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial",size=16)
    pdf.set_section_title_styles(
        # Level 0 titles:
        level0=TitleStyle(
            font_family="Arial",
            font_style="B",
            font_size_pt=24,
            underline=True,
            t_margin=10,
            l_margin=10,
            b_margin=0,
        ),
        level1=TitleStyle(
            font_family="Arial",
            font_style="B",
            font_size_pt=20,
            underline=True,
            t_margin=10,
            l_margin=10,
            b_margin=0,
            color=(89, 89, 89)
        ),
        level2=TitleStyle(
            font_family="Arial",
            font_style="B",
            font_size_pt=16,
            underline=True,
            t_margin=10,
            l_margin=10,
            b_margin=0,
            color=(89, 89, 89)
        )
    )
    pdf.image("SJ.png",x=0, y=0, w=pdf.w,h=pdf.h)
    # Title Page
    pdf.set_xy(137,146)
    version = "v2.0.0"
    pdf.cell(w=31,h=10,text=version,align="C")
    pdf.set_xy(50,190)
    pdf.multi_cell(w=135,h=10,text=f"Scanned By: {username}",border=border_trigger,new_y=YPos.NEXT,new_x=XPos.LEFT)
    pdf.multi_cell(w=135,h=10,text=f"Scan Date: {date}",border=border_trigger,new_y=YPos.NEXT,new_x=XPos.LEFT)
    pdf.multi_cell(w=135,h=10,text=f"Target: {target}",border=border_trigger,new_y=YPos.NEXT,new_x=XPos.LEFT)
    pdf.add_page()
    pdf.insert_toc_placeholder(toc_render)
    pdf.start_section("Executive Summary")
    pdf.y+=5
    pdf.set_font_size(12)
    pdf.multi_cell(w=190,text='''This report provides an overview of the Vulnerability Test Assessment conducted for Greenfossils' Church Management System, addressing the OWASP Top 10 security risks. The assessment aims to identify and evaluate vulnerabilities in the company's web application and infrastructure which enables informed decision-making to enhance the overall security posture.
    ''',new_y=YPos.NEXT, new_x= XPos.LEFT)
    pdf.multi_cell(w=190, text="Conducted Scans: ",new_y=YPos.NEXT, new_x= XPos.LEFT)
    print(conducted_scans)
    for x in conducted_scans:
        pdf.set_left_margin(15)
        pdf.multi_cell(w=190, text="\x95"+" "+x,new_y=YPos.NEXT, new_x= XPos.LEFT)

    table_data= (("High Severity", "Medium Severity", "Low Severity"),(str(high_severity),str(medium_severity),str(low_severity)))
    pdf.start_section("Scan Results")
    pdf.set_left_margin(10)
    pdf.y+=5
    # pdf.multi_cell(w=190, text="The amount")
    with pdf.table(text_align="CENTER") as table:
        for data_row in table_data:
            row= table.row()
            for datum in data_row:
                if datum == "High Severity":
                    row.cell(datum, style=FontFace(fill_color=(194, 64, 64)))
                elif datum == "Medium Severity":
                    row.cell(datum, style=FontFace(fill_color=(227, 135, 16)))
                elif datum == "Low Severity":
                    row.cell(datum, style=FontFace(fill_color=(108, 186, 11)))
                else:
                    row.cell(datum)
    table_data = [("No.", "Vulnerability", "Severity")]
    for i in range(len(vulnerabilities)):
        table_data.append((str(i+1),vulnerabilities[i]['name'],vulnerabilities[i]['severity']))
    pdf.start_section("Our Findings")
    pdf.y+=5
    with pdf.table(width=190,col_widths=(10,120,60),headings_style=FontFace(fill_color=(179, 177, 177),emphasis="BOLD"),text_align="CENTER") as table:
        for data_row in table_data:
            row= table.row()
            for datum in data_row:
                if datum == "High":
                    row.cell(datum, style=FontFace(fill_color=(194, 64, 64)))
                elif datum == "Medium":
                    row.cell(datum, style=FontFace(fill_color=(227, 135, 16)))
                elif datum == "Low":
                    row.cell(datum, style=FontFace(fill_color=(108, 186, 11)))
                else:
                    row.cell(datum)
    pdf.add_page()
    pdf.start_section("Risk Assessment")

    for i in vulnerabilities:
        pdf.start_section(f"{i['name']}",level=1)
        poc_text = ""
        references_text = ""
        poc_text = '\n'.join(i['POC'])
        references_text = '\n'.join(i['references'])
        table_data= (("Vulnerability",),(f"{i['name']}",),("Severity",),(f"{i['severity']}",),("Description",),(f"{i['description']}",),("Proof of Concept",),(f"{poc_text}",),("Recommendations",),(f"{i['recommendations']}",),("References",),(f"{references_text}",))
        height = pdf.font_size*2
        pdf.start_section(f"Description",level=2)
        pdf.y+=5
        pdf.multi_cell(w=190,h=height,text=i['description'],new_y=YPos.NEXT, new_x= XPos.LEFT)
        if(poc_text != ""):
            pdf.start_section(f"Proof of Concept",level=2)
            pdf.y+=5
            pdf.multi_cell(w=190,h=height,text=poc_text, new_y=YPos.NEXT, new_x= XPos.LEFT)
        pdf.start_section(f"Recommendations",level=2)
        pdf.y+=5
        pdf.multi_cell(w=190,h=height,text=i['recommendations'], new_y=YPos.NEXT, new_x= XPos.LEFT)
        if(references_text!=""):
            pdf.start_section(f"References",level=2)
            pdf.y+=5
            pdf.multi_cell(w=190,h=height,text=references_text, new_y=YPos.NEXT, new_x= XPos.LEFT)
        if vulnerabilities.index(i) != len(vulnerabilities)-1: 
            pdf.add_page()

    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    script_directory = os.path.dirname(os.path.abspath(__file__))
    pdf_folder_path = os.path.join(script_directory, 'pdfs')
    os.makedirs(pdf_folder_path, exist_ok=True)
    pdf_file_name = os.path.join(pdf_folder_path, f'report_{current_datetime}_scanned_by_{username}.pdf')
    pdf.output(pdf_file_name)
    return pdf_file_name

@app.route('/download_pdf', methods=['POST'])
def download_pdf(scan_id, user_input):

    connection = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database='vulnerabilities'
    )
    global global_conducted_scans

    # Create a cursor object
    cursor = connection.cursor(buffered=True)#To handle "Unread Result Found"

    #Get scan_id
    # query = "SELECT id from scans where userid = %s"
    # cursor.execute(query,session['userid'])
    # scan_ids = cursor.fetchall()
    # Execute a query to fetch the table data
    query = 'SELECT * FROM vulnerabilities where vulnerabilities.scan_id=%s'
    cursor.execute(query,[scan_id])
    vulnerabilities_data = cursor.fetchall()
    conducted_scans = []
    target_url = user_input
    username = session['username']
    high_severity = 0
    medium_severity = 0
    low_severity = 0
    high_list =[]
    medium_list = []
    low_list = []
    for vulnerability_row in vulnerabilities_data:
        conducted_scans.append(vulnerability_row[2])
        cwe_id = vulnerability_row[3]
        severity = vuln_extract(cwe_id)['severity'].lower()
        if severity == "high":
            high_severity+=1
            high_list.append(vulnerability_row)
        elif severity == "medium":
            medium_severity+=1
            medium_list.append(vulnerability_row)
        elif severity == "low":
            low_severity+=1
            low_list.append(vulnerability_row)
    #Sorted list from high to low
    total_list = high_list + medium_list + low_list
    total_list_dict = []
    for vulnerability in total_list:
        template_dict = {
            "name":"",
            "severity":"",
            "description":"Nothing to include.",
            "POC":[],
            "recommendations":"Nothing to include.",
            "references":[]
        }
        vuln_yaml = vuln_extract(vulnerability[3])
        template_dict['name'] = vuln_yaml['name']
        template_dict['severity'] = vuln_yaml['severity'].title()
        template_dict['description'] = vuln_yaml['description']
        if vuln_yaml['additional_information_check'] == True:
            str_arr = []
            additional_information=vulnerability[5] # Required for the exec
            exec(vuln_yaml["additional_information_parsing"]) #Dangerous, But no choice :(
            template_dict['POC'] = str_arr
        template_dict['recommendations'] = vuln_yaml['solution']
        template_dict['references'] = vuln_yaml['references']
        total_list_dict.append(template_dict)
    query = 'SELECT date_of_scan FROM scans where scans.id=%s'
    cursor.execute(query,[scan_id])
    date_of_scan = cursor.fetchone()[0]

    
    pdf_file_name = pdf_generator(username,date_of_scan,target_url,global_conducted_scans,total_list_dict,high_severity,medium_severity,low_severity)
    
    query = "UPDATE scans set report_name=%s where id=%s"
    cursor.execute(query,[pdf_file_name,scan_id])
    connection.commit()
    cursor.close()
    connection.close()
    # Return the PDF file as an attachment with the formatted file name
    return send_file(pdf_file_name, as_attachment=True)


processes = []
scan_id = None
@app.route('/execute', methods=['POST'])
def execute_script(user_input):
    global processes
    global global_conducted_scans
    global_conducted_scans = []
    user_input = urlsplit(user_input)
    user_input = user_input.scheme + '://' + user_input.netloc
    resp = requests.get(user_input, verify=False)
    if(resp.status_code != 200):
        return -1

    with open('script_to_name_mapping.yaml') as file:
        file_to_name_mapping = yaml.safe_load(file)
    
    connection = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database='vulnerabilities'
    )
    cursor = connection.cursor()
    cursor.execute("INSERT INTO scans(userid,date_of_scan) VALUES(%s,%s)",[session['userid'],datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    connection.commit() 
    g.scan_id = cursor.lastrowid # g is a application context for flask meaning global
    scan_id = g.scan_id
    scripts_folder = 'scripts/'

    # Load the configuration file
    config = configparser.ConfigParser()
    config.read('config.ini')
    crawl_gone = False
    if config.get('Advanced Scan Settings', "crawling", fallback='1')=='1':
        subprocess.run(['python', 'scripts/crawler.py', user_input])
    elif not os.path.isfile("crawl.txt"):#Crawl file does not exist and crawling was not set
        crawl_gone = True
    require_crawl = ["scan_for_forced_browsing","scan_for_insecure_direct_object_references", "scan_for_http_parameter_pollution", 
                     "scan_for_allowed_http_methods", "scan_for_vuln_outdated_components", "scan_for_ssrf", 
                     "scan_for_sql", "scan_for_xss"]
    duplicate_script = [["scan_for_sql","scan_for_xss", "scan_for_ssrf"]]
    for option in file_to_name_mapping['Mapping'].keys():
        script_path = scripts_folder + file_to_name_mapping['Mapping'][option]
        setting_value = config.get('Advanced Scan Settings',option, fallback='1')
        if setting_value == "1" and option in require_crawl and crawl_gone:
            continue # Skip
        if setting_value == '1':
            global_conducted_scans.append(option_to_name_mapping[option])
            for duplicate in duplicate_script:
                if option in duplicate:
                    #check if any of options friends are in processes
                    if len(set([process[0] for process in processes]).intersection(set(duplicate))) > 0: #Friends are there
                        break
            else:
                process = subprocess.Popen(['python', script_path, user_input, str(g.scan_id)])
                processes.append([option,process])
                

    for process in processes:
        process[1].wait()
    processes = []

    g.pop('scan_id')
    print('returning')
    return scan_id

@app.route('/cancel', methods=['POST'])
def cancel_processes():
    for process in processes:
        if os.name == 'nt':  # Windows platform
            process[1].terminate()  # Terminate the process
        else:  # Unix-based platforms
            process.send_signal(signal.SIGTERM)  # Send the termination signal

    if 'scan_id' not in g:
        abort(400, 'Scan not started')
    else:
        db_connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database='vulnerabilities'
        )

        cursor = db_connection.cursor()
        cursor.execute("DELETE FROM scans where id = %s",[g.scan_id])
        g.pop('scan_id')
        username = session['username']
        return redirect('/website2')


@app.route('/get_pdf/<scan_id>', methods=['POST'])
def get_pdf(scan_id):
    
    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database='vulnerabilities'
    )

    cursor = db_connection.cursor(buffered=True)
    #Check whether this user can obtain this scan, <security>
    query = "SELECT report_name from scans where userid=%s and id=%s"
    cursor.execute(query,(session['userid'],scan_id))
    result = cursor.fetchone()
    if(result is None):
        abort(403)
    cursor.close()
    db_connection.close()
    report_path = result[0]
    
    return send_file(report_path)
    
@app.route('/process', methods=['POST'])
def process_input():
    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database='vulnerabilities'
    )

    cursor = db_connection.cursor()

    input_data = request.form['input_field']
    scan_id = execute_script(input_data)
    if scan_id == -1:
        return "Website is down..."
    # input()

    # Load the configuration file
    config = configparser.ConfigParser()
    config.read('config.ini')

    db_connection.commit()
    db.commit()

    download_pdf(scan_id, input_data)

    db_connection.commit()
    db.commit()

    cursor.close()
    db_connection.close()
    
    return redirect('/website4')


@app.route('/website6', methods=['GET', 'POST'])
def config_page():
    # Read the configuration file
    config = configparser.ConfigParser()
    config.read('config.ini')

    print(request.form)
    if request.method == 'POST':
        # Update the configuration based on form submission
        for section in config.sections():
            for key in config[section]:
                if(key in request.form.keys()):
                    if(config[section][key] in ['1','0']):
                        new_value = '1' if request.form.get(key) == 'on' else '0'
                    else:
                        new_value = str(request.form.get(key))
                    config.set(section, key, new_value)
                elif(config[section][key] in ['1','0'] and key not in request.form.keys()): #Since only "on" for checkbox gets sent, this will set things not sent to 0 
                    config.set(section, key, '0')

        # Save the updated configuration to the file+
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    admin = session['admin']

    return render_template('Website6.html', config=config, crawl_file=os.path.isfile("crawl.txt"),username=session['username'], admin=admin)

@app.route('/website2', methods=['GET', 'POST'])
def website2():
    config = configparser.ConfigParser()
    config.read('config.ini')
    #Define OWASP
    if request.method == 'POST':
        # Update the configuration based on form submission
        section="Advanced Scan Settings"
        for key in config[section]:
            if(key in request.form.keys()):
                if(config[section][key] in ['1','0']):
                    new_value = '1' if request.form.get(key) == 'on' else '0'
                else:
                    new_value = str(request.form.get(key))
                config.set(section, key, new_value)
            elif(config[section][key] in ['1','0'] and key not in request.form.keys()): #Since only "on" for checkbox gets sent, this will set things not sent to 0 
                config.set(section, key, '0')

        # Save the updated configuration to the file+
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

        admin = session['admin']
        return render_template('Scan.html', username=session['username'], admin=admin)
    admin = session['admin']
    return render_template('Website2.html', config=config, crawl_file=os.path.isfile("crawl.txt"), username=session['username'], admin=admin)

@app.route('/website7', methods=['GET', 'POST']) # To apply access control later on
def pdf_list():
    #Obtain all reports using scans table
    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database='vulnerabilities'
    )

    db_cursor = db_connection.cursor()
    #Check if user is admin
    if(session['admin']):
        query = "SELECT scans.report_name from scans where report_name IS NOT NULL"
        db_cursor.execute(query,[])
    else:
        query = "SELECT scans.report_name from scans where scans.userid = %s and report_name IS NOT NULL"
        db_cursor.execute(query,[session['userid']])
    results = db_cursor.fetchall()
    db_cursor.close()
    db_connection.close()
    pdf_files = []
    for row in results:
        report_name = row[0]
        #check if the report exists
        if os.path.isfile(report_name):
            pdf_files.append(os.path.split(report_name)[1])#Retrive the filename only
    # pdf_folder = 'pdfs'  # Path to the folder containing the PDF files
    # pdf_files = os.listdir(pdf_folder)  # Get the list of PDF files

    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database='vulnerabilities'
    )
    db_cursor = db_connection.cursor() 
    if(session['admin']):
        query = "SELECT users.username from users"
        db_cursor.execute(query,[])
    else:
        query = "SELECT users.username from users where users.id = %s"
        db_cursor.execute(query,[session['userid']])
    results = db_cursor.fetchall()
    db_cursor.close()
    db_connection.close()
    users = []
    for row in results:
        username = row[0]
        users.append(username)

    admin = session['admin']
    if (request.method == "POST"):
        selectedUser = request.form['selectedUser']
        startDate = request.form['startDate']
        endDate = request.form['endDate']
        for pdf_file in pdf_files[:]:
            date = pdf_file.split("_")[1]
            date = date[0:4]+"-"+date[4:6]+"-"+date[6::]
            if selectedUser != '' and not selectedUser in pdf_file:
                pdf_files.remove(pdf_file)
            if startDate != '' and endDate != '' and not startDate <= date <= endDate:
                pdf_files.remove(pdf_file)
            elif startDate != '' and not startDate <= date:
                pdf_files.remove(pdf_file)
            elif endDate != '' and not date <= endDate:
                pdf_files.remove(pdf_file)
    return render_template('Website7.html', pdf_files=pdf_files, username=session['username'], admin=admin, users=users)

@app.route('/open_pdf', methods=['POST'])
def open_pdf():
    pdf_folder = 'pdfs'  # Path to the folder containing the PDF files
    filename = request.form['filename']
    
    # Create a response with the PDF file
    response = make_response(send_from_directory(pdf_folder, filename))
    response.headers['Content-Type'] = 'application/pdf'
    
    return response

@app.route('/admin')
@admin_required
def index():
    # Fetch all users from the user table
    cursor = db.cursor()
    cursor.execute("select username, admin from users")
    users = cursor.fetchall()
    cursor.close()
    return render_template('Admin.html', users=users)

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user_route():
    # Get the form data submitted by the user
    username = request.form.get('username')
    password = request.form.get('password')
    admin = int(request.form.get('admin', 0))  # Convert to integer (0 or 1)

    try:
        # Insert the new user into the user table
        cursor = db.cursor()
        query = "SELECT * FROM users where username=%s"
        cursor.execute(query,[username])
        result = cursor.fetchall()
        if(len(result) > 0):
            flash(f"User already exists",'error')
            return redirect('/admin')
        query = "INSERT INTO users (username, password, admin) VALUES (%s, %s, %s)"
        password = generate_password_hash(password)
        values = (username, password, admin)
        cursor.execute(query, values)
        db.commit()
        cursor.close()
    except mysql.connector.Error as e:
        # Show the MySQL error as a message box
        flash(f"MySQL Error: {str(e)}", 'error')
        return redirect('/admin')

    return redirect('/admin')


if __name__ == '__main__':
    url = 'http://127.0.0.1:5000'
    webbrowser.open(url)    
    app.run(debug=False)

