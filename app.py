from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "admin":
        return "Welcome, admin!"
    else:
        return "Invalid credentials, please try again."

@app.route("/register")
def register():
    return render_template("register.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
