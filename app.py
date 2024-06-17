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
    # dbcursor.execute("DROP Table user")
    dbcursor.execute("""CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), pwd VARCHAR(255), rsaSk BLOB, rsaPk BLOB, rsaCp BLOB, desKey BLOB, desCp BLOB)""")
    # sql = "DELETE FROM user WHERE username = 'vio'"
    # dbcursor.execute(sql)
    # db.commit()
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
    if(result == None): return "Username not exists."

    # Fetch from db
    sql = "SELECT * FROM user WHERE username = %s"
    uname = (username, )
    dbcursor.execute(sql, uname)
    result = dbcursor.fetchone()
    # print(f"result: {result}")

    # Decrypt in 3 ways
    # RSA
    # print(f"get: {result[3]}\n{result[4]}\nciphertext: {result[5]}")
    rsaPwd = RSA.rsa_decrypt(result[5], result[3])
    print(f"RSA Decryption: {rsaPwd}")

    # DES
    desPwd = DES.des3_decrypt(result[7], result[6])
    print(f"DES Decryption: {desPwd}")

    # Check valid credentials
    if password == rsaPwd and password == desPwd:
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
    # print(f"db: {rsaSk}\n{rsaPk}\nciphertext: {rsaCp}")

    # DES
    desCp, desKey = DES.des3_encrypt(password)
    # print(f"DES key: {desKey}, DES encyrption: {desCp}")

    # AES
    aesCp, aesKey = AES.aes_encrypt(name, password)
    print(f"AES key: {aesKey}, AES encyrption: {aesCp}")

    # Insert DB
    sql = "INSERT INTO user (username, name, pwd, rsaSk, rsaPk, rsaCp, desKey, desCp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    val = (username, name, password, rsaSk, rsaPk, rsaCp, desKey, desCp)
    dbcursor.execute(sql, val)
    db.commit()
    return "Registered successfully!"
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
