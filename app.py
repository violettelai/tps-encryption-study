from flask import Flask, render_template, request, redirect
import mysql.connector
import RSA

app = Flask(__name__)

@app.route("/")
def fetchLoginTemplate():
    return render_template("login.html")

@app.route("/init", methods=["POST"])
def init():
    db = mysql.connector.connect(host="localhost", user="root", password="")
    dbcursor = db.cursor()
    dbcursor.execute("CREATE DATABASE IF NOT EXISTS pysec")   
    dbcursor.execute("USE pysec")
    # dbcursor.execute("DROP Table user")
    dbcursor.execute("CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), pwd VARCHAR(255), rsaSk BLOB, rsaPk BLOB, rsaC BLOB)")
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
    # print(f"result: {result}")

    # Decrypt in 3 ways
    # RSA
    # print(f"get: {result[3]}\n{result[4]}\nciphertext: {result[5]}")
    plaintext = RSA.rsa_decrypt(result[5], result[3])
    # print("Plaintext: {}".format(plaintext))

    # Check valid credentials
    if password == plaintext:
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
    
    db = mysql.connector.connect(host="localhost", user="root", password="", database="pysec")
    dbcursor = db.cursor()
    
    # Check if username duplicated
    sql = "SELECT username FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()
    if(result != None): return "Username exists."
    
    # Encrypt in 3 ways
    # RSA
    privateKey, publicKey = RSA.generateKeys()
    ciphertext = RSA.rsa_encrypt(password, publicKey)
    # print(f"db: {privateKey}\n{publicKey}\nciphertext: {ciphertext}")

    # Insert DB
    sql = "INSERT INTO user (username, pwd, rsaSk, rsaPk, rsaC) VALUES (%s, %s, %s, %s, %s)"
    val = (username, password, privateKey, publicKey, ciphertext)
    dbcursor.execute(sql, val)
    db.commit()
    return "Registered successfully!"
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
