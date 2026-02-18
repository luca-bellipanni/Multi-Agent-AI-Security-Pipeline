"""Sample vulnerable application for testing the AppSec pipeline."""
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        return "Welcome!"
    return "Invalid credentials", 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(f"<h1>Results for: {q}</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f"Registered with hash: {hashed}"
