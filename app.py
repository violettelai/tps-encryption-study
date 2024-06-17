from flask import Flask, render_template, request
import mysql.connector
import RSA, DES, AES
import pandas as pd
import matplotlib.pyplot as plt
import os

app = Flask(__name__)

timing_data = {
    "registration": [],
    "login": []
}

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
    rsaPwd, rsa_decrypt_time = RSA.rsa_decrypt(result[5], result[3])
    rsa_success = password == rsaPwd
    print(f"RSA Decryption: {rsaPwd}")

    # DES
    desPwd, des_decrypt_time = DES.des3_decrypt(result[7], result[6])
    des_success = password == desPwd
    print(f"DES Decryption: {desPwd}")

    #AES    
    aesPwd, aes_decrypt_time = AES.aes_decrypt(result[8], result[9], result[10], result[11], result[12])
    aes_success = password == aesPwd
    print(f"AES Decryption: {aesPwd}")

    # Check valid credentials
    login_success = password == rsaPwd and password == desPwd and password == aesPwd
    
    # Store timing data
    timing_data['login'].append({
        "username": username,
        "password": password,
        "rsa_decryption_time": rsa_decrypt_time,
        "rsa_success": rsa_success,
        "des_decryption_time": des_decrypt_time,
        "des_success": des_success,
        "aes_decryption_time": aes_decrypt_time,
        "aes_success": aes_success
    })

    if login_success:
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
    rsaSk, rsaPk, rsa_keygen_time = RSA.generateKeys()
    rsaCp, rsa_encrypt_time = RSA.rsa_encrypt(password, rsaPk)

    # DES
    desCp, desKey, des_keygen_time, des_encrypt_time = DES.des3_encrypt(password)

    # AES - use name of user as header data
    aesKey, aesNonce, aesHeader, aesTag, aesCp, aes_keygen_time, aes_encrypt_time  = AES.aes_encrypt(name, password)

     # Store timing data
    timing_data['registration'].append({
        "username": username,
        "password": password,
        "rsa_keygen_time": rsa_keygen_time,
        "rsa_encryption_time": rsa_encrypt_time,
        "des_keygen_time": des_keygen_time,
        "des_encryption_time": des_encrypt_time,
        "aes_keygen_time": aes_keygen_time,
        "aes_encryption_time": aes_encrypt_time
    })

    # Insert DB
    sql = "INSERT INTO user (username, name, pwd, rsaSk, rsaPk, rsaCp, desKey, desCp, aesKey, aesNonce, aesHeader, aesTag, aesCp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (username, name, password, rsaSk, rsaPk, rsaCp, desKey, desCp, aesKey, aesNonce, aesHeader, aesTag, aesCp)
    dbcursor.execute(sql, val)
    db.commit()
    return "Registered successfully!"

@app.route("/visualize", methods=['GET'])
def visualize():
    # Set the Matplotlib backend to 'Agg'
    plt.switch_backend('Agg')

    # Create directory if it doesn't exist
    if not os.path.exists('static/img'):
        os.makedirs('static/img')

    # Combine registration and login data
    registration_df = pd.DataFrame(timing_data["registration"])
    login_df = pd.DataFrame(timing_data["login"])

    # Combine DataFrames for Analysis
    combined_df = registration_df.merge(login_df, on="username")

    # Plot Key Generation Times
    plt.figure(figsize=(10, 5))
    plt.bar(combined_df["username"], combined_df["rsa_keygen_time"], label="RSA", alpha=0.7)
    plt.bar(combined_df["username"], combined_df["des_keygen_time"], label="DES", alpha=0.5)
    plt.bar(combined_df["username"], combined_df["aes_keygen_time"], label="AES", alpha=0.3)
    plt.xlabel("Username")
    plt.ylabel("Key Generation Time (ms)")
    plt.title("Key Generation Time by Username")
    plt.legend()
    plt.savefig('static/img/keygen_times.png')
    plt.close()

    # Plot Encryption Times
    plt.figure(figsize=(10, 5))
    plt.bar(combined_df["username"], combined_df["rsa_encryption_time"], label="RSA", alpha=0.7)
    plt.bar(combined_df["username"], combined_df["des_encryption_time"], label="DES", alpha=0.5)
    plt.bar(combined_df["username"], combined_df["aes_encryption_time"], label="AES", alpha=0.3)
    plt.xlabel("Username")
    plt.ylabel("Encryption Time (ms)")
    plt.title("Encryption Time by Username")
    plt.legend()
    plt.savefig('static/img/encryption_times.png')
    plt.close()

    # Plot Decryption Times
    plt.figure(figsize=(10, 5))
    plt.bar(combined_df["username"], combined_df["rsa_decryption_time"], label="RSA", alpha=0.7)
    plt.bar(combined_df["username"], combined_df["des_decryption_time"], label="DES", alpha=0.5)
    plt.bar(combined_df["username"], combined_df["aes_decryption_time"], label="AES", alpha=0.3)
    plt.xlabel("Username")
    plt.ylabel("Decryption Time (ms)")
    plt.title("Decryption Time by Username")
    plt.legend()
    plt.savefig('static/img/decryption_times.png')
    plt.close()

    # Plot Success Rates
    success_rates = {
        "RSA": combined_df["rsa_success"].mean(),
        "DES": combined_df["des_success"].mean(),
        "AES": combined_df["aes_success"].mean()
    }
    plt.figure(figsize=(10, 5))
    plt.bar(success_rates.keys(), success_rates.values(), color=["blue", "orange", "green"])
    plt.xlabel("Encryption Method")
    plt.ylabel("Success Rate")
    plt.title("Success Rate by Encryption Method")
    plt.ylim(0, 1)
    plt.savefig('static/img/success_rates.png')
    plt.close()

    return render_template("visualize.html")
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
