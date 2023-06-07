from flask import *  
import mysql.connector
import hashlib
import flask
from __main__ import app
from ftp_func import get_current_quota, get_used_space, generate_password, create_ftp_user, set_quota, ftp_lock, ftp_unlock, ftp_chpasswd

storage_server = "192.168.1.121"

salt = "this_is_the_salt"
mydb = mysql.connector.connect(
  database="Login",
  host=storage_server,
  user="python",
  password="P@ssw0rd"
)
mycursor = mydb.cursor()

def getEmailByCookie(cookiee):
    mycursor.execute("SELECT password FROM Login;")
    cookie_result = mycursor.fetchall()
    cookie_list = [i[0] for i in cookie_result]
    
    if cookiee in cookie_list :
        mycursor.execute("SELECT email FROM Login where password ='" + cookiee + "';")
        eMail = mycursor.fetchall()[0][0]
        return eMail
    else:
        print("khong phat hien duoc user")
        eMail = "None"
        return eMail

@app.route('/')
def login():
    eMail = getEmailByCookie(request.cookies.get('session'))
    if eMail == "None":
        msg = "Đăng nhập"
    else:
        msg = "Phát hiện tài khoản " + eMail +", Bạn có thể đăng nhập không dùng mật khẩu"
    return render_template("login.html", msg = msg)

@app.route('/login_with_cookie')
def login_with_cookie():
    eMail = getEmailByCookie(request.cookies.get('session'))
    if eMail == "None":
        msg = "Không phát hiện tài khoản, vui lòng đăng nhập sử dụng mật khẩu"
        return render_template("login.html", msg = msg)
    else:
        return render_template('post_login.html', email = eMail)
        
@app.route('/login', methods=['GET', 'POST']) 
def success(): 
    if flask.request.method == 'GET':
        return redirect("/")

    email = request.form['email'] 
    password = request.form['pass']
    hash_password = hashlib.sha256((email + password + salt).encode()).hexdigest()

    sql = "SELECT password FROM Login WHERE email ='" + email + "';"
    mycursor.execute(sql)
    password_result = mycursor.fetchall()
    password_list = [i[0] for i in password_result]
    if password_list == []:
        msg = "Email hoặc mật khẩu không đúng"
        return render_template("login.html", msg = msg)
    if hash_password == password_list[0]:
        resp = make_response(render_template('post_login.html', email = email ))
        resp.set_cookie('session', hash_password)
        resp.set_cookie('email', email)
        return resp
    else:
        msg = "Email hoặc mật khẩu không đúng"
        return render_template("login.html", msg = msg)

@app.route('/signup_form')  
def signup_form():
    return render_template("signup.html")  

@app.route('/signup', methods=['GET', 'POST'])
def signup_success():
    if flask.request.method == 'GET':
        return redirect("/")
    # check xem 2 lan nhap co chuan khong
    email = request.form['email']  
    password = request.form['pass'] 

    if password == "":
        msg = "Chưa nhập password"
        return render_template("signup.html", msg = msg)
    
    if request.form['pass'] != request.form['pass1']:
        msg = "Nhập password lần 2 không chính xác"
        return render_template("signup.html", msg = msg)
    
    # check trung email
    mycursor.execute("SELECT email FROM Login;")
    result = mycursor.fetchall()
    email_list = [i[0] for i in result]
    if email in email_list:
        msg = "Email này đã có người dùng"
        return render_template("signup.html", msg = msg)
    
    #tao tai khoan ftp
    ftp_user= email.split('@')[0] + email.split('@')[1]
    fpt_password = generate_password(8)
    create_ftp_user(ftp_user, fpt_password)

    # insert new user vao database
    str = email + password + salt
    hash = hashlib.sha256(str.encode()).hexdigest()
    sql = "INSERT INTO Login (email, password, ftpUsername, ftpPassword, ftpSize, ftpStatus) VALUES (%s, %s, %s, %s, '10240MB', 'active')"
    val = (email, hash, ftp_user, fpt_password)
    mycursor.execute(sql, val)
    mydb.commit()

    msg = "Đang ký thành công, vui lòng đăng nhập:"
    return redirect(url_for('login', msg = msg))

@app.route('/logout')  
def logout():
    resp = make_response(render_template('login.html'))
    resp.delete_cookie('session')
    resp.delete_cookie('email')
    return resp

@app.route('/chpasswd_form')  
def chpasswd_form():
    return render_template("chpass.html")  

@app.route('/post_chpasswd', methods=['GET', 'POST'])
def chpasswd():
    if flask.request.method == 'GET':
        return redirect("/")
    email = getEmailByCookie(request.cookies.get('session'))
    if email == "None":
        return redirect("/")
     
    if request.form['pass'] != request.form['pass1']:
        msg = "2 mật khẩu không trùng nhau, vui lòng nhập lại"
        return render_template("chpass.html", msg = msg)
       
    old_pass = request.form['old_pass']  
    old_hash_str = email + old_pass + salt
    old_hash = hashlib.sha256(old_hash_str.encode()).hexdigest()
    sql = "SELECT password FROM Login WHERE email ='" + email + "';"
    mycursor.execute(sql)
    password_result = mycursor.fetchall()
    password_list = [i[0] for i in password_result]
    if old_hash != password_list[0]:
        msg = "Mật khẩu cũ không đúng"
        return render_template("chpass.html", msg = msg)
    
    # insert pass moi vao database
    password = request.form['pass'] 
    str = email + password + salt
    hash = hashlib.sha256(str.encode()).hexdigest()
    sql = "UPDATE Login SET password = %s WHERE Email = %s;"
    val = (hash, email)
    mycursor.execute(sql, val)
    mydb.commit()

    resp = make_response(render_template('post_chpass.html'))
    resp.set_cookie('session', hash)
    return resp

@app.route('/viewprofile')  
def profile():
    email = getEmailByCookie(request.cookies.get('session'))
    if email == "None":
        return redirect("/")
    mycursor.execute("SELECT ftpUsername FROM Login WHERE email ='" + email + "';")
    ftp_username_result = mycursor.fetchall()[0][0]
    mycursor.execute("SELECT ftpPassword FROM Login WHERE email ='" + email + "';")
    ftp_password_result = mycursor.fetchall()[0][0]

    quota = get_current_quota(ftp_username_result)
    used_space = get_used_space(ftp_username_result)
    mycursor.execute("SELECT ftpStatus FROM Login WHERE email ='" + email + "';")
    status = mycursor.fetchall()[0][0]

    return render_template('profile.html',name = email, quota = quota, ftp_username_result = ftp_username_result, ftp_password_result = ftp_password_result, used_space = used_space, status = status, ip = storage_server)


@app.route('/ftp_lock', methods=['GET', 'POST'])  
def lock_ftp():
    if flask.request.method == 'GET':
        return redirect("/")
    email = getEmailByCookie(request.cookies.get('session'))
    if email == "None":
        return redirect("/")
    mycursor.execute("UPDATE Login SET ftpStatus = 'deactive' WHERE email ='" + email + "';")
    mydb.commit()
    ftp_user= email.split('@')[0] + email.split('@')[1]
    ftp_lock(ftp_user)
    return redirect("/viewprofile")

@app.route('/ftp_unlock', methods=['GET', 'POST'])  
def unlock_ftp():
    if flask.request.method == 'GET':
        return redirect("/")
    email = getEmailByCookie(request.cookies.get('session'))
    if email == "None":
        return redirect("/")
    mycursor.execute("UPDATE Login SET ftpStatus = 'active' WHERE email ='" + email + "';")
    mydb.commit()
    ftp_user= email.split('@')[0] + email.split('@')[1]
    ftp_unlock(ftp_user)
    return redirect("/viewprofile")

@app.route('/ftp_chpasswd', methods=['GET', 'POST'])  
def ftp_change_passwd():
    if flask.request.method == 'GET':
        return redirect("/")
    email = getEmailByCookie(request.cookies.get('session'))
    if email == "None":
        return redirect("/")
    
    new_ftp_password = generate_password(8)
    ftp_user= email.split('@')[0] + email.split('@')[1]

    mycursor.execute("UPDATE Login SET ftpPassword = '"+ new_ftp_password +"' WHERE email ='" + email + "';")
    mydb.commit()

    ftp_chpasswd(ftp_user, new_ftp_password)
    return redirect("/viewprofile")

################################################################################################ huong dan va download
@app.route('/huong-dan')  
def huongdan():
    return render_template('huong-dan.html')

@app.route('/download', methods=['GET'])  
def download():
    return send_from_directory(directory='bin',  path="FileZilla.exe", as_attachment=True)
