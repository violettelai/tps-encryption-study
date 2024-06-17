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
    dbcursor.execute("CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), pwd VARCHAR(255))")
    return "Database and table successfully created."

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Fetch from db
    
    # Decrypt in 3 ways

    # Check valid credentials
    if username == "admin" and password == "admin":
        return "Welcome, admin!"
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
    
    # Encrypt in 3 ways
    
    # Insert DB

    if password != conpass:
        return "Passwords are not the same!"
    else: 
        return "Registration successful!"
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
