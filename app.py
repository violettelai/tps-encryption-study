from flask import Flask, render_template, request, redirect
import mysql.connector
import RSA, DES, AES

app = Flask(__name__)

@app.route("/")
def fetchLoginTemplate():
    return render_template("login.html")

@app.route("/init", methods=["POST"])
def init():
    # Setup database and table
    db = mysql.connector.connect(host="localhost", user="root", password="")
    dbcursor = db.cursor()
    dbcursor.execute("CREATE DATABASE IF NOT EXISTS pysec")   
    dbcursor.execute("USE pysec")
    dbcursor.execute("CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), pwd VARCHAR(255), rsaSk BLOB, rsaPk BLOB, rsaCp BLOB, desKey BLOB, desCp BLOB, aesKey BLOB, aesNonce BLOB, aesHeader BLOB, aesTag BLOB, aesCp BLOB)")

    return "Database and table successfully created."

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    db = mysql.connector.connect(host="localhost", user="root", password="", database="pysec")
    dbcursor = db.cursor()

    # Check if username exists
    sql = "SELECT username FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()
    if(result == None): return "Username does not exist."

    # Fetch from db
    sql = "SELECT * FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()

    # Decrypt in 3 ways
    # RSA
    rsaPwd = RSA.rsa_decrypt(result[5], result[3])
    print(f"RSA Decryption: {rsaPwd}")

    # DES
    desPwd = DES.des3_decrypt(result[7], result[6])
    print(f"DES Decryption: {desPwd}")

    #AES    
    aesPwd = AES.aes_decrypt(result[8], result[9], result[10], result[11], result[12])
    print(f"AES Decryption: {aesPwd}")

    # Check valid credentials
    if password == rsaPwd and password == desPwd and password == aesPwd:
        return f"Welcome, {result[1]}!"
    else:
        return "Invalid credentials, please try again."

@app.route("/register")
def fetchRegisterTemplate():
    return render_template("register.html")

@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()
    name = data.get("name")
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
    rsaSk, rsaPk = RSA.generateKeys()
    rsaCp = RSA.rsa_encrypt(password, rsaPk)

    # DES
    desCp, desKey = DES.des3_encrypt(password)

    # AES - use name of user as header data
    aesKey, aesNonce, aesHeader, aesTag, aesCp = AES.aes_encrypt(name, password)

    # Insert DB
    sql = "INSERT INTO user (username, name, pwd, rsaSk, rsaPk, rsaCp, desKey, desCp, aesKey, aesNonce, aesHeader, aesTag, aesCp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (username, name, password, rsaSk, rsaPk, rsaCp, desKey, desCp, aesKey, aesNonce, aesHeader, aesTag, aesCp)
    dbcursor.execute(sql, val)
    db.commit()
    return "Registered successfully!"
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
