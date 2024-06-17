from flask import Flask, render_template, request, redirect
import mysql.connector

app = Flask(__name__)

@app.route("/")
def fetchLoginTemplate():
    return render_template("login.html")

@app.route("/init", methods=["POST"])
def init():
    db = mysql.connector.connect(host="localhost", user="root", password="")
    dbcursor = db.cursor()
    dbcursor.execute("CREATE DATABASE IF NOT EXISTS pysec")
    # db = mysql.connector.connect(host="localhost", user="root", password="", database="pysec2")    
    dbcursor.execute("USE pysec")
    # dbcursor = db.cursor()
    dbcursor.execute("CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), pwd VARCHAR(255), rsakey BLOB)")
    return "Database and table successfully created."

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Fetch from db
    db = mysql.connector.connect(host="localhost", user="root", password="", database="pysec")
    dbcursor = db.cursor()
    sql = "SELECT * FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()
    print(f"result: {result}")

    # Decrypt in 3 ways

    # Check valid credentials
    if password == result[2]:
        return f"Welcome, {username}!"
    else:
        return "Invalid credentials, please try again."

@app.route("/register")
def fetchRegisterTemplate():
    return render_template("register.html")

@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conpass = data.get("conpassword")
    
    if password != conpass: return "Passwords are not the same!"
    
    # Encrypt in 3 ways
    
    db = mysql.connector.connect(host="localhost", user="root", password="", database="pysec")
    dbcursor = db.cursor()
    
    # Check if username duplicated
    sql = "SELECT username FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()

    if(result == None):
        # Insert DB
        sql = "INSERT INTO user (username, pwd) VALUES (%s, %s)"
        val = (username, password)
        dbcursor.execute(sql, val)
        db.commit()
        return "Registered successfully!"
    else: return "Username exists."
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
